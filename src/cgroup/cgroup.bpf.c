// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* cgroup: count egress packets per cgroup via cgroup_skb/egress.
 *
 * Attaches to the root cgroup's egress path; each packet increments a per-cpu
 * counter in a map.  Demonstrates cgroup_skb programs for policy/observability.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "cgroup.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} pkt_stats SEC(".maps");

SEC("cgroup_skb/egress")
int count_egress(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct event *e = bpf_map_lookup_elem(&pkt_stats, &key);
	if (e) {
		e->packets += 1;
		e->bytes += skb->len;
	}
	return 1; /* allow the packet */
}
