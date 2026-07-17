// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 50-tcx: a TCX classifier that counts IPv4 packets per interface.
 * TCX links compose automatically (no explicit qdisc/filter needed).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ip_pkts SEC(".maps");

SEC("tcx/ingress")
int tcx_count(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	__u32 key = 0;
	__u64 *cnt;

	if ((void *)(eth + 1) > data_end)
		return 0;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		cnt = bpf_map_lookup_elem(&ip_pkts, &key);
		if (cnt)
			*cnt += 1;
	}
	return 0; /* TC_ACT_OK */
}

char __license[] SEC("license") = "GPL";
