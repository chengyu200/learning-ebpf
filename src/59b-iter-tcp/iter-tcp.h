/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 59b-iter-tcp: TCP 连接扫描器共享定义。
 */
#ifndef __ITER_TCP_H
#define __ITER_TCP_H

struct tcp_event {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 state;
	__u8 pad[3];
};

#endif /* __ITER_TCP_H */
