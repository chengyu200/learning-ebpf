// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 75-netfilter: 内核态 BPF 程序 — netfilter 防火墙。
 *
 * SEC("netfilter") 挂载到 netfilter 框架（与 iptables/nftables 同层）。
 * 上下文为 struct bpf_nf_ctx，含 nf_hook_state + sk_buff。
 *
 * 挂载点：NF_INET_LOCAL_IN（IPv4 INPUT 链）
 *
 * 过滤规则：
 *   1. 丢弃 ICMP（禁止 ping）
 *   2. 丢弃 TCP:8080（禁止访问 8080 端口）
 *   3. 允许其他所有流量（包括 SSH:22）
 *
 * 与 TC/XDP 的关键区别：
 *   - TC/XDP: 上下文是 __sk_buff/xdp_md，用 data/data_end 直接访问包数据
 *   - Netfilter: 上下文是 bpf_nf_ctx，不能用 bpf_skb_load_bytes（此内核不支持）
 *     需用 BPF_CORE_READ 获取 skb->data 指针，再用 bpf_probe_read_kernel 读包数据
 *   - Netfilter: 判决值 NF_ACCEPT/NF_DROP（与 iptables 的 ACCEPT/DROP 相同）
 *
 * 教学概念：
 * - SEC("netfilter") + bpf_program__attach_netfilter()
 * - struct bpf_nf_ctx { state, skb }
 * - BPF_CORE_READ：读取 sk_buff 元数据（如 skb->data, skb->len）
 * - bpf_probe_read_kernel：从 skb->data 指针读取包数据
 * - NF_ACCEPT(1) / NF_DROP(0)：netfilter 判决值
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "netfilter.h"

char LICENSE[] SEC("license") = "GPL";

/* netfilter 判决值（<linux/netfilter.h> 中的宏，不在 BTF 中） */
#define NF_DROP   0
#define NF_ACCEPT 1

#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

/* per-CPU 统计 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stats);
} stats_map SEC(".maps");

/* ringbuf：丢弃事件通道 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("netfilter")
int nf_firewall(struct bpf_nf_ctx *ctx)
{
	struct sk_buff *skb = ctx->skb;
	struct stats *s;
	struct iphdr iph;
	__u32 key = 0;
	__u8 proto;
	__u32 len;
	unsigned char *data;

	s = bpf_map_lookup_elem(&stats_map, &key);
	if (!s)
		return NF_ACCEPT;

	/* 获取 skb->data 指针（在 NF_INET_LOCAL_IN，data 指向网络头/IP 头） */
	data = BPF_CORE_READ(skb, data);
	if (!data)
		return NF_ACCEPT;

	/* 用 bpf_probe_read_kernel 读取 IP 头
	 * （bpf_skb_load_bytes 在 netfilter 程序类型上不可用） */
	if (bpf_probe_read_kernel(&iph, sizeof(iph), data) < 0)
		return NF_ACCEPT;

	/* 只处理 IPv4 */
	if ((*(volatile __u8 *)&iph >> 4) != 4)
		return NF_ACCEPT;

	/* 读取 skb 长度 */
	len = BPF_CORE_READ(skb, len);
	s->packets++;
	s->bytes += len;

	proto = iph.protocol;

	if (proto == IPPROTO_TCP) {
		s->tcp_pkts++;

		/* 读取 TCP 头获取目的端口 */
		__u8 ihl = *(volatile __u8 *)&iph & 0x0f;
		if (ihl >= 5) {
			struct tcphdr tcp;
			__u16 dport;
			__u32 tcp_off = ihl * 4;

			if (bpf_probe_read_kernel(&tcp, sizeof(tcp),
						  data + tcp_off) < 0)
				return NF_ACCEPT;

			dport = bpf_ntohs(tcp.dest);

			/* 规则 2：丢弃 TCP:8080 */
			if (dport == DROP_PORT) {
				s->dropped++;
				struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
				if (e) {
					e->proto  = IPPROTO_TCP;
					e->saddr  = iph.saddr;
					e->daddr  = iph.daddr;
					e->dport  = dport;
					bpf_ringbuf_submit(e, 0);
				}
				return NF_DROP;
			}
		}
	} else if (proto == IPPROTO_UDP) {
		s->udp_pkts++;
	} else if (proto == IPPROTO_ICMP) {
		s->icmp_pkts++;
		s->dropped++;

		/* 规则 1：丢弃 ICMP */
		struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (e) {
			e->proto  = IPPROTO_ICMP;
			e->saddr  = iph.saddr;
			e->daddr  = iph.daddr;
			e->dport  = 0;
			bpf_ringbuf_submit(e, 0);
		}
		return NF_DROP;
	} else {
		s->other_pkts++;
	}

	return NF_ACCEPT;
}
