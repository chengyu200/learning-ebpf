// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 78-tcx-chain: TCX chaining demonstration.
 *
 * Two tcx/ingress programs form a chain on the same interface:
 *   prog_a (first)  -> returns chain_action (TCX_NEXT or TCX_PASS)
 *   prog_b (second) -> always returns TCX_PASS
 *
 * TCX return values (enum tcx_action_base, from bpf.h):
 *   TCX_NEXT  (-1) = continue to next program in chain
 *   TCX_PASS  ( 0) = accept packet, stop chain
 *   TCX_DROP  ( 2) = drop packet, stop chain
 *
 * The global variable 'chain_action' is set by userspace before load:
 *   default:  TCX_NEXT  -> both programs see packets (chain continues)
 *   --pass:   TCX_PASS  -> only prog_a sees packets (chain stops)
 *
 * Note: TC_ACT_PIPE (3) is NOT the correct value for TCX chaining.
 * The kernel maps unknown return codes to TCX_NEXT, but the proper way
 * is to return TCX_NEXT (-1) explicitly.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tcx_chain.h"

#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "GPL";

/* Global variable: set by userspace before load.
 * Default TCX_NEXT (-1) = continue chain.
 * Userspace can set to TCX_PASS (0) = stop chain.
 */
volatile __s32 chain_action = TCX_NEXT;

/* Per-CPU packet counter: index 0 = prog_a, index 1 = prog_b */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} pkt_count SEC(".maps");

static __always_inline void count_pkt(struct __sk_buff *skb, __u32 idx)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return;

	__u64 *cnt = bpf_map_lookup_elem(&pkt_count, &idx);
	if (cnt)
		(*cnt)++;
}

/* Program A: first in the chain.
 * Returns chain_action: TCX_NEXT to continue, TCX_PASS to stop.
 */
SEC("tcx/ingress")
int prog_a(struct __sk_buff *skb)
{
	count_pkt(skb, 0);
	return chain_action;
}

/* Program B: second in the chain.
 * Always returns TCX_PASS (stop chain).
 */
SEC("tcx/ingress")
int prog_b(struct __sk_buff *skb)
{
	count_pkt(skb, 1);
	return TCX_PASS;
}
