// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 41-xdp-tcpdump: capture TCP 5-tuple at the XDP hook. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp-tcpdump.h"

#define ETH_P_IP 0x0800
#define IP_TCP   6

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("xdp")
int xdp_tcpdump(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct event *e;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (struct iphdr *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	if (iph->protocol != IP_TCP)
		return XDP_PASS;

	/* ihl is a 4-bit bitfield in the first byte. */
	__u8 ihl = *(volatile __u8 *)iph & 0x0f;
	tcp = (struct tcphdr *)((void *)iph + ihl * 4);
	if ((void *)(tcp + 1) > data_end)
		return XDP_PASS;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return XDP_PASS;

	e->saddr = iph->saddr;
	e->daddr = iph->daddr;
	e->sport = bpf_ntohs(tcp->source);
	e->dport = bpf_ntohs(tcp->dest);
	e->proto = iph->protocol;
	e->pkt_len = (__u16)(data_end - data);

	bpf_ringbuf_submit(e, 0);
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
