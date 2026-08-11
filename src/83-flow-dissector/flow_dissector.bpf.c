// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 83-flow-dissector: custom BPF flow dissector for IPv4.
 *
 * Program type: BPF_PROG_TYPE_FLOW_DISSECTOR
 * Attach type:   BPF_FLOW_DISSECTOR
 * Attach target: network namespace (via bpf_program__attach_netns)
 * Context:       struct __sk_buff (with skb->flow_keys pointer)
 *
 * The kernel calls this program whenever it needs to compute a flow hash
 * (for RPS/RFS, conntrack, socket matching, etc.). The program parses
 * the packet and fills struct bpf_flow_keys with L3/L4 fields.
 *
 * Return values:
 *   BPF_OK (0)                        = use custom dissection result
 *   BPF_FLOW_DISSECTOR_CONTINUE (129) = fall back to in-kernel dissector
 *
 * struct bpf_flow_keys (filled by this program):
 *   nhoff    = offset from data to network (IP) header
 *   thoff    = offset from data to transport (TCP/UDP) header
 *   n_proto  = L3 protocol (ETH_P_IP, ETH_P_IPV6)
 *   ip_proto = L4 protocol (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP)
 *   ipv4_src, ipv4_dst = source/dest IPv4 (network byte order)
 *   sport, dport       = source/dest L4 port (network byte order)
 *   is_frag, is_first_frag, is_encap = fragmentation/encap flags
 *   flags    = BPF_FLOW_DISSECTOR_F_* control flags
 *   flow_label = IPv6 flow label
 *
 * Data start: depends on interface type.
 *   - Ethernet (veth, eth): data starts at L2 (Ethernet header)
 *   - Loopback (lo): data starts at L3 (IP header, no Ethernet)
 * This program handles both cases by trying L3 first, then L2.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "flow_dissector.h"

#define ETH_P_IP    0x0800
#define ETH_P_8021Q 0x8100
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_ICMP 1

char LICENSE[] SEC("license") = "GPL";

/* Ringbuf: event channel to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Per-CPU call counter: [0]=total calls, [1]=flow_keys non-NULL */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} call_count SEC(".maps");

/* Try to parse IPv4 from a given offset.
 * Returns BPF_OK on success, BPF_FLOW_DISSECTOR_CONTINUE on failure.
 * Sets nhoff/thoff/ip_proto in the output params. */
static __always_inline int try_ipv4(void *data, void *data_end,
				    __u16 nhoff,
				    struct bpf_flow_keys *fk,
				    struct event *e)
{
	struct iphdr *iph = data + nhoff;
	if ((void *)(iph + 1) > data_end)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	if (iph->ihl < 5 || iph->version != 4)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	__u32 thoff = nhoff + iph->ihl * 4;
	__u8 ip_proto = iph->protocol;

	fk->n_proto  = bpf_htons(ETH_P_IP);
	fk->nhoff    = nhoff;
	fk->thoff    = thoff;
	fk->ip_proto = ip_proto;
	fk->ipv4_src = iph->saddr;
	fk->ipv4_dst = iph->daddr;
	fk->is_frag  = !!(iph->frag_off & bpf_htons(0x1FFF));
	fk->is_first_frag = fk->is_frag && !(iph->frag_off & bpf_htons(0x2000));

	/* Parse L4 ports for TCP/UDP */
	if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP) {
		void *l4 = data + thoff;
		if (l4 + 4 <= data_end) {
			fk->sport = *(__be16 *)l4;
			fk->dport = *(__be16 *)(l4 + 2);
			e->sport = bpf_ntohs(*(__be16 *)l4);
			e->dport = bpf_ntohs(*(__be16 *)(l4 + 2));
		}
	}

	e->ipv4_src = iph->saddr;
	e->ipv4_dst = iph->daddr;
	e->ip_proto = ip_proto;
	e->nhoff    = nhoff;
	e->thoff    = thoff;

	return BPF_OK;
}

SEC("flow_dissector")
int dissect_flow(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct bpf_flow_keys *fk = skb->flow_keys;

	/* Increment call counter */
	__u32 zero = 0;
	__u64 *cnt = bpf_map_lookup_elem(&call_count, &zero);
	if (cnt)
		(*cnt)++;

	/* Track if flow_keys was set */
	if (fk) {
		__u32 one = 1;
		__u64 *fk_cnt = bpf_map_lookup_elem(&call_count, &one);
		if (fk_cnt)
			(*fk_cnt)++;
	}

	if (!fk)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	e->sport = 0;
	e->dport = 0;
	e->ts_ns = bpf_ktime_get_ns();

	int ret;

	/* Try L3 first (loopback: data starts at IP header, no Ethernet).
	 * Check if first byte looks like IPv4 (version=4, ihl>=5). */
	struct iphdr *iph = data;
	if ((void *)(iph + 1) <= data_end && iph->version == 4 && iph->ihl >= 5) {
		ret = try_ipv4(data, data_end, 0, fk, e);
		if (ret == BPF_OK) {
			bpf_ringbuf_submit(e, 0);
			return BPF_OK;
		}
	}

	/* Try L2 (Ethernet: data starts at Ethernet header) */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) <= data_end) {
		__be16 n_proto = eth->h_proto;
		__u16 nhoff = sizeof(*eth);  /* 14 */

		/* Handle VLAN tag */
		if (n_proto == bpf_htons(ETH_P_8021Q)) {
			struct vlan_hdr *vlan = (void *)(eth + 1);
			if ((void *)(vlan + 1) > data_end) {
				bpf_ringbuf_discard(e, 0);
				return BPF_FLOW_DISSECTOR_CONTINUE;
			}
			n_proto = vlan->h_vlan_encapsulated_proto;
			nhoff += sizeof(*vlan);  /* +4 */
		}

		if (n_proto == bpf_htons(ETH_P_IP)) {
			ret = try_ipv4(data, data_end, nhoff, fk, e);
			if (ret == BPF_OK) {
				bpf_ringbuf_submit(e, 0);
				return BPF_OK;
			}
		}
	}

	/* Non-IPv4 or unparseable: fall back to kernel dissector */
	bpf_ringbuf_discard(e, 0);
	return BPF_FLOW_DISSECTOR_CONTINUE;
}
