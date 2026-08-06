// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 71-netkit: 用户态加载器。
 *
 * 功能：
 *   1. 创建 netkit 设备对（L3 模式）
 *   2. 配置 IP 地址
 *   3. 加载 BPF 程序，分别 attach 到 primary 和 peer 端
 *   4. 每秒打印两端统计（包数/字节数/丢弃数）
 *   5. Ctrl-C 时清理（detach + 删除设备）
 *
 * 典型部署（Cilium 模型）：primary 在 host，peer 在 container netns。
 * primary 留在宿主机的好处：不需要 setns 就能 attach BPF 程序。
 *
 * 用法：
 *   sudo ./netkit
 *   # 另开终端测试：
 *   #   nc 10.0.0.2 8080                          → 被 primary 丢弃（TCP:8080, host→container）
 *   #   ip netns exec nkns ping 10.0.0.1        → 被 peer 丢弃（ICMP, container→host）
 *   #   nc -l -p 9000 &                           → 正常（非 8080 端口）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "netkit.h"
#include "netkit.skel.h"

#define NK_PRIMARY "nk0"
#define NK_PEER    "nk1"
#define NK_NETNS   "nkns"
#define NK_IP_PRI  "10.0.0.1"
#define NK_IP_PEER "10.0.0.2"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* 执行 shell 命令 */
static void run_cmd(const char *cmd)
{
	int ret = system(cmd);
	printf("run command: %s\n", cmd);
	if (ret != 0)
		fprintf(stderr, "  cmd failed (ret=%d): %s\n", ret, cmd);
}

/* 创建并配置 netkit 设备对（使用 netns，netkit 必须跨 netns 才能通信）
 *
 * 典型部署（Cilium 模型）：primary 留在宿主机 netns，peer 移入容器 netns。
 * primary 在宿主机侧的好处：直接 attach BPF 程序，不需要 setns。
 */
static void setup_netkit(void)
{
	char cmd[256];

	/* 清理可能残留的设备和 netns（先删 netns 再删设备） */
	run_cmd("ip netns del " NK_NETNS " 2>/dev/null");
	sleep(1);
	run_cmd("ip link del " NK_PRIMARY " 2>/dev/null");
	sleep(1);

	/* 创建 netns（模拟容器网络命名空间） */
	run_cmd("ip netns add " NK_NETNS);

	/* 创建 netkit L3 设备对：nk0=primary, nk1=peer */
	snprintf(cmd, sizeof(cmd),
		 "ip link add %s type netkit mode l3 peer %s",
		 NK_PRIMARY, NK_PEER);
	run_cmd(cmd);

	/* primary (nk0) 留在宿主机 netns（典型部署：primary 在 host 侧） */
	snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s",
		 NK_IP_PRI, NK_PRIMARY);
	run_cmd(cmd);
	snprintf(cmd, sizeof(cmd), "ip link set %s up", NK_PRIMARY);
	run_cmd(cmd);

	/* peer (nk1) 移入容器 netns */
	snprintf(cmd, sizeof(cmd), "ip link set %s netns %s",
		 NK_PEER, NK_NETNS);
	run_cmd(cmd);
	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip addr add %s/24 dev %s",
		 NK_NETNS, NK_IP_PEER, NK_PEER);
	run_cmd(cmd);
	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip link set %s up", NK_NETNS, NK_PEER);
	run_cmd(cmd);
	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip link set lo up", NK_NETNS);
	run_cmd(cmd);
}

/* 删除 netkit 设备和 netns */
static void cleanup_netkit(void)
{
	/* peer 在 netns 中，先尝试删除 */
	run_cmd("ip netns exec " NK_NETNS " ip link del " NK_PEER " 2>/dev/null");
	/* 删除 primary 会自动删除对端 */
	run_cmd("ip link del " NK_PRIMARY " 2>/dev/null");
	run_cmd("ip netns del " NK_NETNS " 2>/dev/null");
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
	if (bpf_map_lookup_elem(map_fd, &key, vals) == 0)
		for (int i = 0; i < ncpu; i++) {
			total.packets += vals[i].packets;
			total.bytes += vals[i].bytes;
			total.dropped += vals[i].dropped;
		}
	free(vals);
	return total;
}

int main(int argc, char **argv)
{
	struct netkit_bpf *skel;
	struct bpf_link *pri_link = NULL, *peer_link = NULL;
	int err = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	/* ── 第 1 步：创建 netkit 设备对 ── */
	printf("Creating netkit device pair (L3 mode)...\n");
	setup_netkit();
	sleep(1);

	/* primary (nk0) 在宿主机 netns，直接获取 ifindex。
	 * peer (nk1) 在容器 netns 中，需要 setns 获取 ifindex（仅用于显示）。 */
	int pri_ifindex = if_nametoindex(NK_PRIMARY);
	int peer_ifindex = 0;

	char path[256];
	snprintf(path, sizeof(path), "/var/run/netns/%s", NK_NETNS);
	int default_netns = open("/proc/self/ns/net", O_RDONLY);
	int netns_fd = open(path, O_RDONLY);
	if (netns_fd >= 0 && default_netns >= 0) {
		if (setns(netns_fd, CLONE_NEWNET) == 0) {
			peer_ifindex = if_nametoindex(NK_PEER);
			setns(default_netns, CLONE_NEWNET);
		}
	}
	if (netns_fd >= 0)
		close(netns_fd);
	if (default_netns >= 0)
		close(default_netns);

	if (!pri_ifindex || !peer_ifindex) {
		fprintf(stderr, "Failed to get ifindex: pri=%d peer=%d\n",
			pri_ifindex, peer_ifindex);
		err = 1;
		goto cleanup;
	}
	printf("  %s (primary, ifindex=%d, in host) <-> %s (peer, ifindex=%d, in %s)\n",
	       NK_PRIMARY, pri_ifindex, NK_PEER, peer_ifindex, NK_NETNS);

	/* ── 第 2 步：加载 BPF 骨架 ── */
	skel = netkit_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		err = 1;
		goto cleanup;
	}

	err = netkit_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* ── 第 3 步：attach primary 和 peer 程序 ──
	 *
	 * primary 在宿主机 netns 中，直接 attach，不需要 setns！
	 * 这是 primary 留在 host 的好处：宿主机可以直接管理 BPF 程序。
	 *
	 * 关键：内核的 netkit_dev_fetch() 要求所有 BPF 操作都通过 primary 设备。
	 * 无论是 attach primary 程序还是 peer 程序，都必须传入 primary 设备的
	 * ifindex。内核通过 attach_type 区分：
	 *   SEC("netkit/primary") → attach_type=BPF_NETKIT_PRIMARY → 在 primary 上 attach
	 *   SEC("netkit/peer")    → attach_type=BPF_NETKIT_PEER    → 内核从 primary 找到 peer，在 peer 上 attach
	 *
	 * 如果传入 peer 设备的 ifindex，netkit_dev_fetch() 会检查 nk->primary，
	 * 发现 primary=false，返回 -EACCES。
	 */
	pri_link = bpf_program__attach_netkit(skel->progs.primary_filter,
					     pri_ifindex, NULL);
	peer_link = bpf_program__attach_netkit(skel->progs.peer_filter,
					      pri_ifindex, NULL);

	if (!pri_link) {
		fprintf(stderr, "attach primary failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}
	if (!peer_link)
		fprintf(stderr, "attach peer failed (ignored): %s\n", strerror(errno));

	int pri_map = bpf_map__fd(skel->maps.primary_stats);
	int peer_map = bpf_map__fd(skel->maps.peer_stats);

	printf("\nBPF programs attached:\n");
	printf("  Primary (%s in host): drop TCP:8080 (host → container, container ingress)\n", NK_PRIMARY);
	printf("  Peer    (%s in %s): drop ICMP (container → host, container egress)\n\n", NK_PEER, NK_NETNS);
	printf("Test:\n");
	printf("  nc %s 8080                     → dropped by primary (TCP:8080, host→container)\n", NK_IP_PEER);
	printf("  ip netns exec %s ping %s     → dropped by peer (ICMP, container→host)\n", NK_NETNS, NK_IP_PRI);
	printf("  ip netns exec %s nc %s 9000  → passed (non-8080 port)\n", NK_NETNS, NK_IP_PRI);
	printf("\n%-6s  %-26s  %-26s\n", "sec",
	       "PRIMARY (host→container)", "PEER (container→host)");
	printf("       %8s %8s %8s  %8s %8s %8s\n",
	       "pkts", "bytes", "dropped", "pkts", "bytes", "dropped");
	printf("──────  ────────────────────────────  ────────────────────────────\n");

	/* ── 第 4 步：每秒打印统计 ── */
	for (int sec = 1; !exiting; sec += 3) {
		sleep(3);
		struct stats pri = read_stats(pri_map);
		struct stats peer = read_stats(peer_map);

		printf("%-6d  %8llu %8llu %8llu  %8llu %8llu %8llu\n",
		       sec,
		       pri.packets, pri.bytes, pri.dropped,
		       peer.packets, peer.bytes, peer.dropped);
	}

	/* 最终总结 */
	struct stats pri_final = read_stats(pri_map);
	struct stats peer_final = read_stats(peer_map);
	printf("\n═══════════════════════════════════════════════════════\n");
	printf("  Summary\n");
	printf("═══════════════════════════════════════════════════════\n");
	printf("  Primary: %llu packets, %llu dropped\n",
	       pri_final.packets, pri_final.dropped);
	printf("  Peer:    %llu packets, %llu dropped\n",
	       peer_final.packets, peer_final.dropped);
	printf("═══════════════════════════════════════════════════════\n");

cleanup:
	if (peer_link)
		bpf_link__destroy(peer_link);
	if (pri_link)
		bpf_link__destroy(pri_link);
	if (skel)
		netkit_bpf__destroy(skel);
	printf("\nCleaning up netkit devices...\n");
	cleanup_netkit();
	return err < 0 ? -err : 0;
}
