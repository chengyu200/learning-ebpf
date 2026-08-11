/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 83-flow-dissector: custom flow dissector shared definitions.
 */
#ifndef __FLOW_DISSECTOR_H
#define __FLOW_DISSECTOR_H

#define TASK_COMM_LEN 16

/* Ringbuf event: logged for each dissected IPv4 packet */
struct event {
	__u32 ipv4_src;		/* source IP (network byte order) */
	__u32 ipv4_dst;		/* dest IP (network byte order) */
	__u16 sport;		/* source port (host byte order) */
	__u16 dport;		/* dest port (host byte order) */
	__u8  ip_proto;		/* L4 protocol: TCP(6), UDP(17), ICMP(1) */
	__u8  _pad[3];
	__u16 nhoff;		/* network header offset */
	__u16 thoff;		/* transport header offset */
	__u64 ts_ns;
};

#endif /* __FLOW_DISSECTOR_H */
