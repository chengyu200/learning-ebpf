// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 71-netkit: 内核态 BPF 程序。
 *
 * 两个 BPF 程序分别挂载到 netkit 设备对的两端：
 *
 *   Primary（nk0，在宿主机 netns 中）：在 primary 发送时运行 → host→container
 *     - 丢弃 TCP:8080（禁止宿主机访问容器的 8080 端口）
 *     = 容器的 ingress 过滤
 *
 *   Peer（nk1，在容器 netns 中）：在 peer 发送时运行 → container→host
 *     - 丢弃 ICMP（禁止容器 ping 宿主机）
 *     = 容器的 egress 过滤
 *
 * BPF 程序运行在发送端的 netkit_xmit() 路径：
 *   primary 发送 (host→container) → BPF_NETKIT_PRIMARY 运行
 *   peer 发送 (container→host)    → BPF_NETKIT_PEER 运行
 *
 * 典型部署（Cilium 模型）：primary 在 host，peer 在 pod/container。
 * primary 留在宿主机的好处：不需要 setns 就能 attach BPF 程序。
 *
 * 教学概念：
 * - BPF_NETKIT_PRIMARY / BPF_NETKIT_PEER：netkit 设备的两个 attach 点
 * - L3 模式：skb 仍包含以太网头（需跳过 14 字节）
 * - NETKIT_PASS(0) / NETKIT_DROP(2)：返回值语义
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "netkit.h"

#define NETKIT_PASS  0
#define NETKIT_DROP  2
#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define ETH_HLEN     14

/* primary 端统计（host→container 的包，primary 发送时计数） */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stats);
} primary_stats SEC(".maps");

/* peer 端统计（container→host 的包，peer 发送时计数） */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stats);
} peer_stats SEC(".maps");

/* 解析 IP 头并提取协议号和 L4 端口 */
static __always_inline int parse_skb(struct __sk_buff *skb, __u8 *proto,
				     __u16 *dport)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	__u8 ihl;

	if ((void *)(eth + 1) > data_end)
		return -1;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return -1;

	ihl = *(volatile __u8 *)iph & 0x0f;
	*proto = iph->protocol;

	if (*proto == IPPROTO_TCP && ihl >= 5) {
		struct tcphdr *tcp = (void *)iph + ihl * 4;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		*dport = bpf_ntohs(tcp->dest);
	} else {
		*dport = 0;
	}

	return 0;
}

/* ── Primary 端（宿主机 netns 中）：丢弃 host→container 的 TCP:8080 ──
 * BPF_NETKIT_PRIMARY 在 primary 发送时运行 = host→container 方向 = 容器 ingress */
SEC("netkit/primary")
int primary_filter(struct __sk_buff *skb)
{
	__u8 proto = 0;
	__u16 dport = 0;
	__u32 key = 0;
	struct stats *s;

	s = bpf_map_lookup_elem(&primary_stats, &key);
	if (!s)
		return NETKIT_PASS;

	s->packets++;
	s->bytes += skb->len;

	if (parse_skb(skb, &proto, &dport) < 0)
		return NETKIT_PASS;

	/* 丢弃目标端口 8080 的 TCP 包（禁止宿主机访问容器的 8080） */
	if (proto == IPPROTO_TCP && dport == 8080) {
		s->dropped++;
		return NETKIT_DROP;
	}

	return NETKIT_PASS;
}

/* ── Peer 端（容器 netns 中）：丢弃 container→host 的 ICMP ──
 * BPF_NETKIT_PEER 在 peer 发送时运行 = container→host 方向 = 容器 egress */
SEC("netkit/peer")
int peer_filter(struct __sk_buff *skb)
{
	__u8 proto = 0;
	__u16 dport = 0;
	__u32 key = 0;
	struct stats *s;

	s = bpf_map_lookup_elem(&peer_stats, &key);
	if (!s)
		return NETKIT_PASS;

	s->packets++;
	s->bytes += skb->len;

	if (parse_skb(skb, &proto, &dport) < 0)
		return NETKIT_PASS;

	/* 丢弃 ICMP（禁止容器 ping 宿主机） */
	if (proto == IPPROTO_ICMP) {
		s->dropped++;
		return NETKIT_DROP;
	}

	return NETKIT_PASS;
}

char __license[] SEC("license") = "GPL";
