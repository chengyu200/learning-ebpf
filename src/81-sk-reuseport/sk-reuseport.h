/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 81-sk-reuseport: 共享定义。
 */
#ifndef __SK_REUSEPORT_H
#define __SK_REUSEPORT_H

#define TASK_COMM_LEN 16
#define NUM_SOCKETS 3

/* 事件类型 */
enum op_type {
	OP_SELECT  = 1,	/* 新连接选择 */
	OP_MIGRATE = 2,	/* 连接迁移 */
};

/* ringbuf 事件 */
struct event {
	__u8  op;		/* enum op_type */
	__u8  selected;		/* 选择的 socket 索引 */
	__u8  _pad[2];
	__u32 hash;		/* 包 4-tuple hash */
	__u32 ip_protocol;	/* IPPROTO_TCP / UDP */
	__u32 pid;
	char  comm[TASK_COMM_LEN];
};

#endif /* __SK_REUSEPORT_H */
