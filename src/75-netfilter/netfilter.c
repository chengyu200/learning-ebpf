// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 75-netfilter: 用户态加载器 + 统计打印。
 *
 * 功能：
 *   1. 加载 BPF 程序
 *   2. bpf_program__attach_netfilter 挂载到 NF_INET_LOCAL_IN (IPv4 INPUT)
 *   3. 每秒打印 per-CPU 统计（TCP/UDP/ICMP/other 的 pkts/bytes/dropped）
 *   4. ringbuf 回调打印丢弃事件
 *   5. Ctrl-C 清理
 *
 * 用法：
 *   sudo ./netfilter
 *   # 另开终端测试：
 *   #   ping -c 1 127.0.0.1        → 被 DROP（ICMP）
 *   #   nc -l -p 8080 &             → 起 server
 *   #   nc 127.0.0.1 8080           → 被 DROP（TCP:8080）
 *   #   nc 127.0.0.1 22             → 正常（SSH 不受影响）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "netfilter.h"
#include "netfilter.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* 读取 per-CPU map 并汇总 */
static struct stats read_stats(int map_fd)
{
	struct stats total = {};
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	struct stats *vals = calloc(ncpu, sizeof(struct stats));
	__u32 key = 0;

	if (!vals)
		return total;
	if (bpf_map_lookup_elem(map_fd, &key, vals) == 0) {
		for (int i = 0; i < ncpu; i++) {
			total.packets   += vals[i].packets;
			total.bytes     += vals[i].bytes;
			total.dropped    += vals[i].dropped;
			total.tcp_pkts  += vals[i].tcp_pkts;
			total.udp_pkts  += vals[i].udp_pkts;
			total.icmp_pkts += vals[i].icmp_pkts;
			total.other_pkts += vals[i].other_pkts;
		}
	}
	free(vals);
	return total;
}

static const char *proto_str(__u8 proto)
{
	switch (proto) {
	case 1:  return "ICMP";
	case 6:  return "TCP";
	case 17: return "UDP";
	default: return "?";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	char saddr[32], daddr[32];
	struct in_addr a;

	a.s_addr = e->saddr;
	strncpy(saddr, inet_ntoa(a), sizeof(saddr) - 1);
	saddr[sizeof(saddr)-1] = '\0';
	a.s_addr = e->daddr;
	strncpy(daddr, inet_ntoa(a), sizeof(daddr) - 1);
	daddr[sizeof(daddr)-1] = '\0';

	if (e->proto == 1) {
		printf("[DROP] %-5s %s → %s\n", proto_str(e->proto), saddr, daddr);
	} else {
		printf("[DROP] %-5s %s → %s:%d\n",
		       proto_str(e->proto), saddr, daddr, e->dport);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct netfilter_bpf *skel;
	struct bpf_link *link = NULL;
	struct ring_buffer *ringbuf = NULL;
	int err = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	/* 1. 加载 skeleton */
	skel = netfilter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load skeleton\n");
		return 1;
	}

	/* 2. attach 到 NF_INET_LOCAL_IN (IPv4 INPUT 链) */
	LIBBPF_OPTS(bpf_netfilter_opts, opts,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = 0,
	);

	link = bpf_program__attach_netfilter(skel->progs.nf_firewall, &opts);
	if (!link) {
		fprintf(stderr, "attach_netfilter failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 3. 设置 ringbuf */
	int map_fd = bpf_map__fd(skel->maps.stats_map);
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	printf("BPF netfilter firewall attached to NF_INET_LOCAL_IN (IPv4 INPUT)\n");
	printf("  Rule 1: DROP ICMP (ping blocked)\n");
	printf("  Rule 2: DROP TCP:%d (port blocked)\n", DROP_PORT);
	printf("  Rule 3: ACCEPT all other (SSH:22 OK)\n\n");
	printf("Test:\n");
	printf("  ping -c 1 127.0.0.1         → DROP (ICMP)\n");
	printf("  nc 127.0.0.1 %d              → DROP (TCP:%d)\n", DROP_PORT, DROP_PORT);
	printf("  nc 127.0.0.1 22              → ACCEPT (SSH OK)\n\n");
	printf("proto     pkts    bytes  dropped\n");
	printf("──────  ────────  ────────  ────────\n");

	/* 4. 每3秒打印统计 */
	while (!exiting) {
		sleep(3);
		struct stats s = read_stats(map_fd);

		printf("TCP     %6llu  %8llu  %6llu\n", s.tcp_pkts,  s.bytes, 0ULL);
		printf("UDP     %6llu  %8s  %6s\n",   s.udp_pkts,  "-",      "-");
		printf("ICMP    %6llu  %8s  %6llu\n",  s.icmp_pkts, "-",      s.dropped);
		printf("Other   %6llu  %8s  %6s\n",   s.other_pkts,"-",      "-");
		printf("──────  ────────  ────────  ────────\n");
		printf("Total   %6llu  %8llu  %6llu\n\n", s.packets, s.bytes, s.dropped);

		ring_buffer__poll(ringbuf, 100);
	}

cleanup:
	ring_buffer__free(ringbuf);
	if (link)
		bpf_link__destroy(link);
	if (skel)
		netfilter_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
