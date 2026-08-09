/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 75-netfilter: 共享定义。
 */
#ifndef __NETFILTER_H
#define __NETFILTER_H

#define DROP_PORT 8080

/* per-CPU 统计结构 */
struct stats {
	__u64 packets;
	__u64 bytes;
	__u64 dropped;
	__u64 tcp_pkts;
	__u64 udp_pkts;
	__u64 icmp_pkts;
	__u64 other_pkts;
};

/* ringbuf 丢弃事件 */
struct event {
	__u8 proto;		/* IPPROTO_TCP / IPPROTO_ICMP */
	__u8 _pad[3];
	__u32 saddr;		/* 源 IP（网络字节序） */
	__u32 daddr;		/* 目的 IP（网络字节序） */
	__u16 dport;		/* 目的端口（主机字节序） */
	__u16 _pad2;
};

#endif /* __NETFILTER_H */
