// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 56-xdp-cpumap: 用户态 — 创建 cpumap + attach XDP + 周期统计。
 *
 * 流程：
 *   1. open_and_load skeleton
 *   2. 为每个 CPU 填充 cpumap（qsize + cpumap prog fd）
 *   3. attach ingress 程序：先试 DRV mode，失败回退 SKB mode
 *   4. 每 2 秒读取 per-CPU 计数，打印分布表格
 *   5. Ctrl-C 退出，detach
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp-cpumap.h"
#include "xdp-cpumap.skel.h"

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t report_flag;

static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		exiting = 1;
	else if (sig == SIGALRM)
		report_flag = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void print_stats(struct xdp_cpumap_bpf *skel, int ncpu)
{
	__u32 key = 0;
	__u64 *rx_vals, *cm_vals;
	__u64 total_rx = 0, total_cm = 0;

	rx_vals = calloc(ncpu, sizeof(__u64));
	cm_vals = calloc(ncpu, sizeof(__u64));
	if (!rx_vals || !cm_vals)
		goto out;

	if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.rx_cnt),
			       &key, rx_vals) != 0)
		goto out;
	if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.cpumap_cnt),
			       &key, cm_vals) != 0)
		goto out;

	printf("\n=== Per-CPU Packet Distribution ===\n\n");
	printf("  %-6s %-16s %-20s\n", "CPU", "RX(ingress)", "CPUMAP(processed)");
	printf("  %-6s %-16s %-20s\n", "------", "----------------", "--------------------");

	for (int i = 0; i < ncpu; i++) {
		total_rx += rx_vals[i];
		total_cm += cm_vals[i];
		if (rx_vals[i] > 0 || cm_vals[i] > 0)
			printf("  %-6d %-16llu %-20llu\n", i, rx_vals[i], cm_vals[i]);
	}

	printf("\n  Total RX: %llu    Total CPUMAP: %llu", total_rx, total_cm);
	if (total_rx > 0)
		printf("    Redirect rate: %llu%%\n", total_cm * 100 / total_rx);
	else
		printf("\n");

	fflush(stdout);

out:
	free(rx_vals);
	free(cm_vals);
}

int main(int argc, char **argv)
{
	struct xdp_cpumap_bpf *skel;
	const char *ifname = "vethbpf0";
	int ifindex, err, ncpu, prog_fd, cpumap_fd;
	int attach_mode = XDP_FLAGS_DRV_MODE;
	const char *mode_str = "DRV";

	if (argc > 1)
		ifname = argv[1];

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);

	ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1)
		ncpu = 1;
	if (ncpu < 2) {
		fprintf(stderr, "need at least 2 CPUs for CPUMAP redirect demo\n");
		return 1;
	}
	if (ncpu > MAX_CPUS)
		ncpu = MAX_CPUS;

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "interface %s not found\n", ifname);
		return 1;
	}

	skel = xdp_cpumap_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	/* 填充 cpumap：为每个 CPU 写入 bpf_cpumap_val（qsize + cpumap prog fd） */
	cpumap_fd = bpf_map__fd(skel->maps.cpumap);
	prog_fd = bpf_program__fd(skel->progs.xdp_cpumap_prog);

	for (int i = 0; i < ncpu; i++) {
		struct bpf_cpumap_val val = {
			.qsize = CPUMAP_QSIZE,
			.bpf_prog.fd = prog_fd,
		};
		__u32 key = i;
		err = bpf_map_update_elem(cpumap_fd, &key, &val, BPF_ANY);
		if (err) {
			fprintf(stderr, "cpumap update cpu %d: %s\n", i, strerror(errno));
			goto cleanup;
		}
	}
	printf("cpumap: %d CPUs configured (qsize=%d, prog_fd=%d)\n",
	       ncpu, CPUMAP_QSIZE, prog_fd);

	/* attach ingress 程序：先试 DRV mode */
	prog_fd = bpf_program__fd(skel->progs.xdp_redirect_cpu);
	err = bpf_xdp_attach(ifindex, prog_fd, attach_mode, NULL);
	if (err) {
		fprintf(stderr, "DRV mode attach failed: %s, trying SKB mode...\n",
			strerror(errno));
		attach_mode = XDP_FLAGS_SKB_MODE;
		mode_str = "SKB";
		err = bpf_xdp_attach(ifindex, prog_fd, attach_mode, NULL);
		if (err) {
			fprintf(stderr, "SKB mode attach also failed: %s\n",
				strerror(errno));
			goto cleanup;
		}
	}

	printf("xdp-cpumap: redirecting on %s (%s mode)\n", ifname, mode_str);
	printf("Press Ctrl-C to stop.\n");

	if (strcmp(mode_str, "SKB") == 0)
		fprintf(stderr, "WARNING: SKB mode — bpf_redirect_map to cpumap may not work!\n");

	alarm(5);

	while (!exiting) {
		if (report_flag) {
			report_flag = 0;
			print_stats(skel, ncpu);
			alarm(5);
		}
		pause();
	}

	print_stats(skel, ncpu);

cleanup:
	bpf_xdp_detach(ifindex, attach_mode, NULL);
	xdp_cpumap_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
