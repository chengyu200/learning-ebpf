// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 20-tc: print IP packet info at the tc ingress hook.
 *
 * Kernel side: a tc classifier attached to the clsact qdisc's ingress hook.
 * For every IPv4 packet it prints the total length and TTL via bpf_printk.
 * Teaches: tc attachment, __sk_buff parsing (data/data_end bounds checks),
 * L2/L3 header walking.
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	bpf_printk("tc: IP packet tot_len=%d ttl=%d",
		   bpf_ntohs(l3->tot_len), l3->ttl);
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
