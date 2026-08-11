/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 82-cgroup-skb: Cgroup dual-direction traffic audit shared definitions.
 */
#ifndef __CGROUP_SKB_H
#define __CGROUP_SKB_H

#define TASK_COMM_LEN 16

/* Event direction */
#define DIR_INGRESS 0
#define DIR_EGRESS  1

/* Ringbuf event */
struct event {
	__u8  direction;	/* DIR_INGRESS or DIR_EGRESS */
	__u8  allowed;		/* 1=allowed, 0=denied */
	__u8  _pad[2];
	__u32 pid;
	__u32 protocol;		/* L4 protocol: IPPROTO_TCP(6), IPPROTO_UDP(17), IPPROTO_ICMP(1) */
	__u32 pkt_len;		/* skb->len */
	__u32 port;		/* TCP/UDP port (dport for egress, sport for ingress) */
	__u64 ts_ns;
	__u64 sock_cookie;	/* bpf_get_socket_cookie */
	char  comm[TASK_COMM_LEN];
};

#define DEMO_CGROUP "/sys/fs/cgroup/cg-skb-demo"

#endif /* __CGROUP_SKB_H */
