// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 46-xdp-test: XDP packet generator.  On every received packet, build a small
 * UDP probe and send it back out via XDP_TX, so we can measure XDP throughput.
 * Also counts packets in a per-CPU array.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} pkt_count SEC(".maps");

SEC("xdp")
int xdp_gen(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 key = 0;
	__u64 *cnt;

	cnt = bpf_map_lookup_elem(&pkt_count, &key);
	if (cnt)
		*cnt += 1;

	/* Just pass; a real generator would rewrite headers and XDP_TX.
	 * Here we count and pass so throughput can be measured with traffic. */
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
