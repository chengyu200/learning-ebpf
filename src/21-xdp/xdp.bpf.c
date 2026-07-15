// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 21-xdp: print packet size at the XDP hook.
 *
 * Kernel side: an XDP program attached in SKB mode (works on any interface,
 * including lo/veth without driver XDP support).  Prints each packet's size via
 * bpf_printk and passes the packet up to the stack.
 * Teaches: xdp_md context, data/data_end, XDP actions.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int pkt_sz = data_end - data;

	bpf_printk("xdp: packet size %d", pkt_sz);
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
