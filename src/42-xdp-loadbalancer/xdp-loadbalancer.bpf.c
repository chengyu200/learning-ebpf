// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 42-xdp-loadbalancer: L4 load balancer — hash the 5-tuple and pick a backend,
 * rewriting the destination IP and MAC and forwarding via bpf_redirect_peer to
 * a veth peer.  Teaches XDP packet rewriting + redirect.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "xdp-loadbalancer.h"

#define ETH_P_IP 0x0800
#define IP_TCP   6

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_BACKENDS);
	__type(key, __u32);
	__type(value, struct backend);
} backends SEC(".maps");

const volatile __u32 target_daddr = 0; /* IPv4 to balance, net order */
const volatile __u32 ifindex_peer = 0;

static __always_inline __u32 hash5(__u32 a, __u32 b, __u16 c, __u16 d)
{
	__u32 h = a ^ b ^ (c << 16 | d);
	h = h * 0x9e3779b1u;
	return h;
}

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

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (struct iphdr *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	if (target_daddr && iph->daddr != target_daddr)
		return XDP_PASS;
	if (iph->protocol != IP_TCP)
		return XDP_PASS;

	__u8 ihl = *(volatile __u8 *)iph & 0x0f;
	tcp = (struct tcphdr *)((void *)iph + ihl * 4);
	if ((void *)(tcp + 1) > data_end)
		return XDP_PASS;

	key = hash5(iph->saddr, iph->daddr, tcp->source, tcp->dest) % MAX_BACKENDS;
	be = bpf_map_lookup_elem(&backends, &key);
	if (!be)
		return XDP_DROP;

	/* Rewrite dst IP + MAC; fix IP checksum via incremental update. */
	__u32 old_daddr = iph->daddr;
	__u32 new_daddr = be->addr;
	__u32 csum = ~iph->check;
	csum += (new_daddr & 0xFFFF) + (new_daddr >> 16);
	csum -= (old_daddr & 0xFFFF) + (old_daddr >> 16);
	csum = (csum & 0xFFFF) + (csum >> 16);
	iph->check = ~(csum + (csum >> 16));
	iph->daddr = new_daddr;

	__builtin_memcpy(eth->h_dest, be->mac, 6);

	if (ifindex_peer)
		return bpf_redirect_peer(ifindex_peer, 0);
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
