// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 82-cgroup-skb: Cgroup dual-direction traffic audit + egress port policy.
 *
 * Program type: BPF_PROG_TYPE_CGROUP_SKB
 * Context:     struct __sk_buff (same as TC, but no sk_skb-specific fields)
 *
 * Three SEC names:
 *   1. SEC("cgroup_skb/ingress") — BPF_CGROUP_INET_INGRESS
 *      Count incoming packets, log to ringbuf, allow all.
 *   2. SEC("cgroup_skb/egress")  — BPF_CGROUP_INET_EGRESS
 *      Count outgoing packets, log to ringbuf, drop TCP egress to blocked port.
 *   3. SEC("cgroup/skb") (bare) — legacy/generic form (attach_type=0, SEC_NONE)
 *      Documented in comments; not used in this example.
 *
 * Return values: 1 = allow (pass), 0 = deny (drop).
 *   This is the filter-style convention (non-zero = pass), NOT the TC convention
 *   where TCX_PASS=0 and TCX_DROP=2.
 *
 * Packet data: cgroup_skb can access data/data_end. For cgroup_skb, the
 * data typically starts at the L3 (IP) header (no Ethernet header).
 *
 * struct __sk_buff fields accessible to cgroup_skb:
 *   len, protocol, data, data_end, mark, priority, hash, etc.
 *   NOT accessible: family, local_port, remote_port (those are sk_skb-only).
 *   sk: struct bpf_sock * (socket pointer, for bpf_get_socket_cookie).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "cgroup_skb.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

/* Config map: blocked egress port (1 entry). 0 = no blocking. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cfg_block_port SEC(".maps");

/* Ringbuf: event channel to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct event *new_event(struct __sk_buff *skb, __u8 direction, __u8 allowed)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return NULL;
	e->direction = direction;
	e->allowed = allowed;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ts_ns = bpf_ktime_get_ns();
	e->sock_cookie = bpf_get_socket_cookie(skb);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

/* Parse L4 port from packet data.
 * For egress: read destination port (TCP/UDP header offset).
 * For ingress: read source port.
 * Returns 0 if not parseable.
 */
static __always_inline __u32 parse_port(struct __sk_buff *skb, __u8 direction)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	/* Try parsing as IP header (cgroup_skb data starts at L3) */
	struct iphdr *iph = data;
	if ((void *)(iph + 1) > data_end)
		return 0;

	/* Check IPv4 */
	if (iph->ihl < 5 || iph->version != 4)
		return 0;

	__u8 proto = iph->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return 0;

	/* L4 header follows IP header */
	__u32 ihl = iph->ihl * 4;
	void *l4 = (void *)iph + ihl;
	if (l4 + 4 > data_end)
		return 0;

	/* TCP/UDP: first 4 bytes are sport(2) + dport(2) */
	__u16 sport = bpf_ntohs(*(__u16 *)l4);
	__u16 dport = bpf_ntohs(*(__u16 *)(l4 + 2));

	return direction == DIR_EGRESS ? dport : sport;
}

static __always_inline __u8 get_l4_proto(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data;
	if ((void *)(iph + 1) > data_end)
		return 0;
	if (iph->version != 4)
		return 0;
	return iph->protocol;
}

/* 1. cgroup_skb/ingress — count incoming packets, log to ringbuf, allow all */
SEC("cgroup_skb/ingress")
int count_ingress(struct __sk_buff *skb)
{
	struct event *e = new_event(skb, DIR_INGRESS, 1);
	if (e) {
		e->protocol  = get_l4_proto(skb);
		e->pkt_len   = skb->len;
		e->port      = parse_port(skb, DIR_INGRESS);
		bpf_ringbuf_submit(e, 0);
	}
	return 1;  /* allow all ingress */
}

/* 2. cgroup_skb/egress — count outgoing, drop TCP to blocked port */
SEC("cgroup_skb/egress")
int filter_egress(struct __sk_buff *skb)
{
	__u8 l4_proto = get_l4_proto(skb);
	__u32 dport = parse_port(skb, DIR_EGRESS);
	__u8 allowed = 1;

	/* Check if this port is blocked */
	__u32 key = 0;
	__u32 *blocked = bpf_map_lookup_elem(&cfg_block_port, &key);
	if (blocked && *blocked != 0 && l4_proto == IPPROTO_TCP && dport == *blocked)
		allowed = 0;

	struct event *e = new_event(skb, DIR_EGRESS, allowed);
	if (e) {
		e->protocol  = l4_proto;
		e->pkt_len   = skb->len;
		e->port      = dport;
		bpf_ringbuf_submit(e, 0);
	}

	return allowed;
}

/*
 * 3. SEC("cgroup/skb") (bare) — legacy/generic form.
 *    attach_type = 0, SEC_NONE flag. Does not auto-attach.
 *    In older kernels, this was the only form available; the kernel
 *    would use it for both ingress and egress. Modern code should use
 *    the explicit "cgroup_skb/ingress" or "cgroup_skb/egress" instead.
 */
