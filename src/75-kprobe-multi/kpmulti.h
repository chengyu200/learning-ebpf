/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 75-kprobe-multi: 多函数 kprobe 追踪共享定义。
 */
#ifndef __KPMULTI_H
#define __KPMULTI_H

#define TASK_COMM_LEN 16
#define MAX_FUNC_LEN 64

#define EVENT_ENTRY   1
#define EVENT_RETURN  2
#define EVENT_LATENCY 3

struct event {
	__u8  type;       /* EVENT_ENTRY / EVENT_RETURN / EVENT_LATENCY */
	__u8  pad[7];
	__u32 pid;
	__u64 ip;         /* 函数地址（ENTRY/RETURN） */
	__u64 latency_ns; /* 延迟（仅 LATENCY） */
	char comm[TASK_COMM_LEN];
};

#endif /* __KPMULTI_H */
