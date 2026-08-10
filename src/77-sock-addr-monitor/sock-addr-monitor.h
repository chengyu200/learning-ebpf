/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 77-sock-addr-monitor: 共享定义。
 */
#ifndef __SOCK_ADDR_MONITOR_H
#define __SOCK_ADDR_MONITOR_H

#define TASK_COMM_LEN 16
#define IP6_STR_LEN   48

/* 操作类型：对应 17 个 hook */
enum op_type {
	OP_BIND4 = 1,
	OP_BIND6,
	OP_CONNECT4,
	OP_CONNECT6,
	OP_CONNECT_UNIX,
	OP_SENDMSG4,
	OP_SENDMSG6,
	OP_SENDMSG_UNIX,
	OP_RECVMSG4,
	OP_RECVMSG6,
	OP_RECVMSG_UNIX,
	OP_GETPEERNAME4,
	OP_GETPEERNAME6,
	OP_GETPEERNAME_UNIX,
	OP_GETSOCKNAME4,
	OP_GETSOCKNAME6,
	OP_GETSOCKNAME_UNIX,
};

/* ringbuf 事件 */
struct event {
	__u8  op;		/* enum op_type */
	__u8  _pad[3];
	__u32 user_family;	/* 用户传入的地址族 */
	__u32 sock_type;	/* SOCK_STREAM / SOCK_DGRAM */
	__u32 protocol;		/* IPPROTO_TCP / UDP */
	__u32 ip4;		/* user_ip4（网络字节序） */
	__u32 ip6[4];		/* user_ip6（网络字节序） */
	__u16 port;		/* user_port（主机字节序） */
	__u16 _pad2;
	__u32 pid;
	char  comm[TASK_COMM_LEN];
};

#define DEMO_CGROUP "/sys/fs/cgroup/cg-sock-monitor"

#endif /* __SOCK_ADDR_MONITOR_H */
