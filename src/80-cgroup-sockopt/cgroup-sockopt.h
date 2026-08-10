/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 80-cgroup-sockopt: 共享定义。
 */
#ifndef __CGROUP_SOCKOPT_H
#define __CGROUP_SOCKOPT_H

#define TASK_COMM_LEN 16

/* socket option levels */
#define SOL_SOCKET 1
#define SOL_IP      0

/* SOL_SOCKET option names */
#define SO_REUSEADDR 2
#define SO_KEEPALIVE 9
#define SO_TYPE      3

/* SOL_IP option names */
#define IP_TTL       2

/* errno */
#define EPERM        1
#define ENOMEM       12

/* 事件操作类型 */
enum op_type {
	OP_SETSOCKOPT = 1,
	OP_GETSOCKOPT = 2,
};

/* 决策类型 */
enum decision {
	DEC_ALLOWED   = 0,
	DEC_BLOCKED   = 1,
	DEC_REWRITTEN = 2,
};

/* ringbuf 事件 */
struct event {
	__u8  op;		/* enum op_type */
	__u8  decision;		/* enum decision */
	__u8  _pad[2];
	__s32 level;
	__s32 optname;
	__s32 optlen;
	__s32 rewritten_val;	/* 改写后的值（getsockopt） */
	__u32 pid;
	char  comm[TASK_COMM_LEN];
};

#define DEMO_CGROUP "/sys/fs/cgroup/cg-sockopt-demo"

#endif /* __CGROUP_SOCKOPT_H */
