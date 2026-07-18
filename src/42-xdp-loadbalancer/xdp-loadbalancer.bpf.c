// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 42-xdp-loadbalancer: 内核态 XDP L4 负载均衡器
 *
 * 本程序在 XDP（eXpress Data Path）钩点上运行，早于内核协议栈处理每个包。
 * 工作流程：
 *   1. 解析以太网 → IP → TCP 各层头部
 *   2. 对 TCP 五元组做哈希，选择一个后端服务器
 *   3. 重写目的 IP 地址 + 目的 MAC 地址
 *   4. 增量更新 IP 校验和（无需重新计算整个包）
 *   5. 通过 bpf_redirect_peer 将包转发到对端网卡
 *
 * 教学概念：
 * - XDP 程序类型（SEC("xdp")）：在驱动层处理包，性能最高
 * - xdp_md 上下文：data/data_end 指针直接访问包数据
 * - BPF_MAP_TYPE_ARRAY：用户态预填充后端列表
 * - IP 校验和增量更新：修改 IP 头后只重算变化的部分
 * - bpf_redirect_peer：将包转发到另一个网卡的对端
 *
 * 数据包结构（XDP 视角，从 data 开始）：
 *   [以太网头 14B][IP头 20B+][TCP头 20B+][payload...]
 *    ^- data       ^- iph     ^- tcp
 *
 * 与 lesson 21（xdp-pass）和 lesson 41（xdp-tcpdump）的区别：
 * - 21 只观察包大小（XDP_PASS）
 * - 41 解析五元组后输出（XDP_PASS）
 * - 本示例修改包内容并转发（XDP_REDIRECT）
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "xdp-loadbalancer.h"

#define ETH_P_IP 0x0800   /* EtherType: IPv4 */
#define IP_TCP   6        /* IP 协议号: TCP */

/*
 * 后端服务器列表（array map）
 * 用户态在 load 后通过 bpf_map__update_elem 填充：
 *   key=0 → backend[0], key=1 → backend[1], ...
 * BPF 程序根据哈希结果查询此 map。
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_BACKENDS);
	__type(key, __u32);
	__type(value, struct backend);
} backends SEC(".maps");

/*
 * 全局配置变量（用户态在 load 前设置）
 * target_daddr: 需要负载均衡的目标 IP（网络字节序）。
 *               只有目的地址匹配的包才会被负载均衡，其他包直接放行。
 *               设为 0 表示对所有 IPv4/TCP 包做负载均衡。
 * ifindex_peer: 对端网卡的 ifindex，用于 bpf_redirect_peer 转发。
 *               设为 0 时不转发（仅修改包，然后 XDP_PASS）。
 */
const volatile __u32 target_daddr = 0;
const volatile __u32 ifindex_peer = 0;

/*
 * 简单的 TCP 五元组哈希函数
 *
 * 用源IP、目的IP、源端口、目的端口计算一个 32 位哈希值。
 * 同一个连接的包（正向和反向）会产生不同的哈希值，
 * 但同一个方向的包始终哈希到同一个后端，保证连接亲和性。
 *
 * 0x9e3779b1 是黄金分割常数（2^32 / φ），常用于哈希混合。
 *
 * @a: 源 IP 地址
 * @b: 目的 IP 地址
 * @c: 源端口
 * @d: 目的端口
 * @return 32 位哈希值
 */
static __always_inline __u32 hash5(__u32 a, __u32 b, __u16 c, __u16 d)
{
	__u32 h = a ^ b ^ (c << 16 | d);
	h = h * 0x9e3779b1u;
	return h;
}

/*
 * XDP 负载均衡主函数
 *
 * 每个到达网卡的数据包都会调用此函数。
 * 返回值决定包的命运：
 *   XDP_PASS    → 交给内核协议栈正常处理
 *   XDP_DROP    → 直接丢弃
 *   XDP_REDIRECT → 转发到其他网卡/Socket
 *
 * @ctx  XDP 上下文（xdp_md），包含 data/data_end 等指针
 * @return XDP 动作码
 */
SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct backend *be;
	__u32 key;

	/* ── 第 1 层：解析以太网头 ──
	 * 边界检查：确保以太网头完整存在于 data ~ data_end 范围内。
	 * 这是 BPF verifier 的强制要求：任何指针解引用前必须做边界检查。 */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* 只处理 IPv4 包（EtherType = 0x0800） */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* ── 第 2 层：解析 IP 头 ── */
	iph = (struct iphdr *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	/* 如果配置了目标 IP，只对发往该 IP 的包做负载均衡 */
	if (target_daddr && iph->daddr != target_daddr)
		return XDP_PASS;

	/* 只处理 TCP 包 */
	if (iph->protocol != IP_TCP)
		return XDP_PASS;

	/* ── 第 3 层：解析 TCP 头 ──
	 * IP 头长度 IHL 存储在 IP 头第一个字节的低 4 位（以 4 字节为单位）。
	 * 通常 IHL=5（即 20 字节），但如果有 IP 选项则更长。
	 * 注意：iphdr.ihl 是位域，不能直接用 offsetof，所以直接读第一个字节。 */
	__u8 ihl = *(volatile __u8 *)iph & 0x0f;
	tcp = (struct tcphdr *)((void *)iph + ihl * 4);
	if ((void *)(tcp + 1) > data_end)
		return XDP_PASS;

	/* ── 第 4 步：哈希选择后端 ──
	 * 用五元组哈希 → 取模 → 得到后端索引
	 * 同一连接的包始终哈希到同一后端（连接亲和性） */
	key = hash5(iph->saddr, iph->daddr, tcp->source, tcp->dest) % MAX_BACKENDS;
	be = bpf_map_lookup_elem(&backends, &key);
	if (!be)
		return XDP_DROP;  /* 后端未配置，丢弃包 */

	/* ── 第 5 步：重写目的 IP 地址 ──
	 * 将原始目的 IP 替换为后端服务器 IP */
	__be32 old_daddr = iph->daddr;
	__be32 new_daddr = be->addr;

	/* ── 第 6 步：用 bpf_csum_diff 增量更新 IP 校验和 ──
	 *
	 * IP 校验和是反码和（ones' complement sum）。
	 * 修改了 daddr 字段后，校验和需要增量更新：
	 *   new_check = old_check - old_daddr + new_daddr
	 *
	 * bpf_csum_diff 是 BPF 辅助函数（helper #28），对 XDP 程序可用。
	 * 它计算 from → to 的校验和差值（反码和），返回 __wsum（32 位）。
	 *
	 * 参数：
	 *   from       = 旧值数组指针（old_daddr，4 字节）
	 *   from_size  = 旧值字节数（4）
	 *   to         = 新值数组指针（new_daddr，4 字节）
	 *   to_size    = 新值字节数（4）
	 *   seed       = 初始种子（这里用旧校验和的反码作为种子，
	 *                这样结果直接包含旧校验和的累加）
	 *
	 * 计算结果 ~diff 即为新的校验和。 */
	__wsum csum_diff = bpf_csum_diff(&old_daddr, sizeof(old_daddr),
					&new_daddr, sizeof(new_daddr),
					~iph->check);
	iph->check = ~csum_diff;

	/* 写入新的目的 IP */
	iph->daddr = new_daddr;

	/* ── 第 7 步：重写目的 MAC 地址 ──
	 * 以太网帧需要正确的目的 MAC 才能被目标网卡接收。
	 * 将目的 MAC 替换为后端服务器的 MAC。 */
	__builtin_memcpy(eth->h_dest, be->mac, 6);

	/* ── 第 8 步：转发包 ──
	 * bpf_redirect_peer：将包转发到指定网卡（ifindex_peer），
	 * 并且从对端网卡的视角看，包就像是从该网卡收到的。
	 * 如果未配置 ifindex_peer（=0），则只修改包但不转发（XDP_PASS），
	 * 修改后的包会走内核协议栈正常处理。 */
	if (ifindex_peer)
		return bpf_redirect_peer(ifindex_peer, 0);
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
