// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 76-tc-tcx: 用户态 — attach 四个 TC/TCX 程序 + per-CPU 统计。
 *
 * 流程：
 *   1. 确保 veth 对存在（setup-veth.sh）
 *   2. 加载 BPF skeleton
 *   3. 用 bpf_program__attach_tcx 分别 attach 四个程序到 vethbpf0
 *   4. 周期打印 per-CPU 包计数和字节计数
 *   5. Ctrl-C 退出，自动 detach
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tc_tcx.h"
#include "tc_tcx.skel.h"

static char *g_ifname = "vethbpf0";
static int g_interval = 2;
static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *prog_names[] = {
	[0] = "tc/ingress",
	[1] = "tc/egress",
	[2] = "tcx/ingress",
	[3] = "tcx/egress",
};

static void print_stats(struct tc_tcx_bpf *skel, int ncpu)
{
	__u64 pkts[4] = {}, bytes[4] = {};
	__u64 *vals;

	vals = calloc(ncpu, sizeof(__u64));
	if (!vals)
		return;

	for (int i = 0; i < 4; i++) {
		__u32 key = i;
		memset(vals, 0, ncpu * sizeof(__u64));
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.pkt_count), &key, vals) == 0)
			for (int c = 0; c < ncpu; c++)
				pkts[i] += vals[c];
		memset(vals, 0, ncpu * sizeof(__u64));
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.byte_count), &key, vals) == 0)
			for (int c = 0; c < ncpu; c++)
				bytes[i] += vals[c];
	}

	printf("%-16s %10s %12s\n", "Program", "Packets", "Bytes");
	printf("%-16s %10s %12s\n", "--------", "-------", "-----");
	for (int i = 0; i < 4; i++)
		printf("%-16s %10llu %12llu\n", prog_names[i], pkts[i], bytes[i]);
	printf("\n");

	free(vals);
}

int main(int argc, char **argv)
{
	struct tc_tcx_bpf *skel;
	struct bpf_link *links[4] = {};
	int err = 0, ifindex, ncpu;

	if (argc > 1) g_ifname = argv[1];
	if (argc > 2) g_interval = atoi(argv[2]);

	ifindex = if_nametoindex(g_ifname);
	if (!ifindex) {
		fprintf(stderr, "interface %s not found. Run: sudo ./scripts/setup-veth.sh create\n", g_ifname);
		return 1;
	}
	ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1) ncpu = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	skel = tc_tcx_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	/* attach 程序到网卡。
	 *
	 * TCX chaining: 同一 hook 点上的多个程序形成链。
	 * TCX_PASS(0) 停止链，TCX_NEXT(-1) 继续链（见 78-tcx-chain）。
	 * 本示例所有程序返回 TCX_PASS，链在第一个程序后停止。
	 * 因此同一 hook 上的第二个程序看不到包（tcx/ingress 为 0）。 */
	struct bpf_program *progs[4];
	progs[0] = skel->progs.tc_ingress;    /* tc/ingress */
	progs[1] = skel->progs.tc_egress;     /* tc/egress */
	progs[2] = skel->progs.tcx_ingress;   /* tcx/ingress */
	progs[3] = skel->progs.tcx_egress;    /* tcx/egress */
//	progs[2] = skel->progs.tc_ingress;
//	progs[3] = skel->progs.tc_egress;
//	progs[0] = skel->progs.tcx_ingress;
//	progs[1] = skel->progs.tcx_egress;

	for (int i = 0; i < 4; i++) {
		LIBBPF_OPTS(bpf_tcx_opts, opts);
		links[i] = bpf_program__attach_tcx(progs[i], ifindex, &opts);
		if (!links[i]) {
			fprintf(stderr, "attach %s failed: %s\n", prog_names[i], strerror(errno));
			err = -errno;
			goto cleanup;
		}
	}

	printf("TC/TCX programs attached to %s.\n", g_ifname);
	printf("Note: tc/ingress and tcx/ingress attach to the same hook (aliases).\n");
	printf("      TCX chaining: first program returns TCX_PASS, stops chain.\n");
	printf("      So only tc/ingress and tc/egress see packets.\n");
	printf("Generate traffic: sudo ip netns exec bpfns ping 192.168.99.1\n\n");

	while (!exiting) {
		sleep(g_interval);
		print_stats(skel, ncpu);
	}

cleanup:
	for (int i = 0; i < 4; i++)
		if (links[i])
			bpf_link__destroy(links[i]);
	tc_tcx_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
