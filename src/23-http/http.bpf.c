// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
/* 23-http: kernel-side socket filter that parses TCP/IPv4 and forwards the
 * first bytes of the payload (HTTP request line, etc.) to user space.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "http.h"

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP    6
#define ETH_HLEN  14

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off),
			   &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct so_event *e;
	__u8 verlen;
	__u16 proto;
	__u32 nhoff = ETH_HLEN;
	__u32 ip_proto = 0;
	__u32 tcp_hdr_len = 0;
	__u16 tlen;
	__u32 payload_offset = 0;
	__u32 payload_length = 0;
	__u8 hdr_len;

	if (skb->protocol != __bpf_ntohs(0x0800 /* ETH_P_IP */))
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pkt_type = skb->pkt_type;
	e->ifindex = skb->ifindex;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol),
			   &ip_proto, 1);
	if (ip_proto != IP_TCP)
		goto out;

	if (ip_is_fragment(skb, nhoff))
		goto out;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr),
			   &e->src_addr, 4);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr),
			   &e->dst_addr, 4);

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len),
			   &tlen, sizeof(tlen));
	e->ports = 0;
	/* ihl is a 4-bit bitfield in the first byte of struct iphdr. */
	bpf_skb_load_bytes(skb, nhoff, &verlen, 1);
	hdr_len = verlen & 0x0f;
	tcp_hdr_len = hdr_len * 4;
	payload_offset = ETH_HLEN + hdr_len * 4 + 14; /* +tcp hdr estimate */

	bpf_skb_load_bytes(skb, nhoff + hdr_len * 4, &e->port16, 4);
	e->port16[0] = __bpf_ntohs(e->port16[0]);
	e->port16[1] = __bpf_ntohs(e->port16[1]);
	e->ip_proto = ip_proto;

	payload_length = __bpf_ntohs(tlen) - hdr_len * 4 - 20;
	if (payload_length > MAX_BUF_SIZE)
		payload_length = MAX_BUF_SIZE;
	if (payload_length > 0) {
		bpf_skb_load_bytes(skb, payload_offset, e->payload,
				payload_length);
	}
	e->payload_length = payload_length;

out:
	bpf_ringbuf_submit(e, 0);
	return 0;
}
