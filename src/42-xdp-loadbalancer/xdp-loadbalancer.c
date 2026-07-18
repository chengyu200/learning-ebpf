// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 42-xdp-loadbalancer: 用户态加载器
 *
 * 本程序负责：
 *   1. 加载 XDP BPF 程序（骨架 open + load）
 *   2. 从命令行参数填充后端服务器列表到 BPF map
 *   3. 将 XDP 程序挂载到指定网卡（SKB 模式，兼容所有网卡）
 *   4. 等待 Ctrl-C，退出时 detach
 *
 * 用法：
 *   sudo ./xdp-loadbalancer <网卡名> <后端IP1> [后端IP2] ...
 *
 * 示例：
 *   sudo ./xdp-loadbalancer vethbpf0 192.168.99.2 192.168.99.3
 *
 * 教学概念：
 * - bpf_xdp_attach：将 XDP 程序挂到网卡（SKB 模式 vs 驱动模式）
 * - bpf_map__update_elem：在 load 后动态填充 BPF map
 * - XDP_FLAGS_SKB_MODE：通用模式，兼容 lo/veth 等虚拟网卡
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp-loadbalancer.h"
#include "xdp-loadbalancer.skel.h"

/* 默认绑定的网卡名（可通过命令行参数覆盖） */
static char *g_ifname = "vethbpf0";
static volatile sig_atomic_t exiting;

/* ── 信号处理 ── */
static void sig_handler(int sig) { exiting = 1; }

/*
 * libbpf 日志回调：控制 libbpf 输出级别。
 * DEBUG 级别默认不打印（避免刷屏）。
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

/*
 * 主函数
 *
 * argv[1] = 网卡名（如 vethbpf0, lo）
 * argv[2..] = 后端服务器 IP 地址列表（最多 MAX_BACKENDS 个）
 *
 * 示例：
 *   ./xdp-loadbalancer vethbpf0 10.0.0.2 10.0.0.3 10.0.0.4
 */
int main(int argc, char **argv)
{
	struct xdp_loadbalancer_bpf *skel;
	int ifindex, err, prog_fd, i;

	/* 解析网卡名 */
	if (argc > 1) g_ifname = argv[1];
	ifindex = if_nametoindex(g_ifname);
	if (!ifindex) {
		fprintf(stderr, "if %s not found\n", g_ifname);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* ── 第 1 步：加载 BPF 骨架 ──
	 * open_and_load = open + load + map_create 一步到位
	 * 此时 backends map 为空，需要下一步填充 */
	skel = xdp_loadbalancer_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	/* ── 第 2 步：填充后端服务器列表 ──
	 * 从命令行参数 argv[2..] 读取后端 IP，写入 BPF array map。
	 * key=0 对应 backend[0], key=1 对应 backend[1], ...
	 * MAC 地址留零（L3 模式下 veth 对端不检查 MAC） */
	for (i = 2; i < argc && i - 2 < MAX_BACKENDS; i++) {
		struct backend be = {};
		if (inet_pton(AF_INET, argv[i], &be.addr) != 1) {
			/* inet_pton 返回 1 表示成功解析 IPv4 地址 */
			fprintf(stderr, "bad backend ip: %s\n", argv[i]);
			continue;
		}
		__u32 key = i - 2;
		/* bpf_map__update_elem 在 load 后、attach 前更新 map
		 * （此时 map fd 已创建，可直接写入） */
		bpf_map__update_elem(skel->maps.backends, &key, sizeof(key),
				     &be, sizeof(be), BPF_ANY);
		printf("backend[%u] = %s\n", key, argv[i]);
	}

	/* ── 第 3 步：将 XDP 程序挂载到网卡 ──
	 * XDP_FLAGS_SKB_MODE：SKB 模式（也叫 generic 模式）
	 *   - 在内核协议栈的 skb 分配后运行
	 *   - 兼容所有网卡（包括 lo、veth 等虚拟网卡）
	 *   - 性能低于驱动模式（native mode），但通用性好
	 * 驱动模式（不加 flag）需要网卡驱动支持 XDP */
	prog_fd = bpf_program__fd(skel->progs.xdp_lb);
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err) {
		fprintf(stderr, "xdp attach: %s\n", strerror(-err));
		goto cleanup;
	}

	/* ── 第 4 步：等待退出 ── */
	printf("xdp-loadbalancer on %s... Ctrl-C\n", g_ifname);
	while (!exiting)
		sleep(1);

	/* ── 第 5 步：清理 ── 从网卡 detach XDP 程序 */
	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

cleanup:
	xdp_loadbalancer_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
