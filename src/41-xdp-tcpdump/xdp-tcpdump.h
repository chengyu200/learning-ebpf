/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __XDP_TCPDUMP_H
#define __XDP_TCPDUMP_H

#define TASK_COMM_LEN 16

struct event {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 proto;
	__u16 pkt_len;
};

#endif
