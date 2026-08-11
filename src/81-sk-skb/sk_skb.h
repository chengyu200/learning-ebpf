/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 81-sk-skb: SK_SKB stream parser + verdict shared definitions.
 */
#ifndef __SK_SKB_H
#define __SK_SKB_H

#define TASK_COMM_LEN 16

/* Ringbuf event */
struct event {
	__u32 msg_size;		/* total message size (header + payload) */
	__u32 payload_len;	/* payload length from header */
	__u32 local_port;	/* server port (host byte order) */
	__u32 remote_port;	/* client port (network byte order) */
	__u32 family;		/* AF_INET, AF_INET6 */
	__u32 pid;
	__u64 ts_ns;
	char  comm[TASK_COMM_LEN];
};

#endif /* __SK_SKB_H */
