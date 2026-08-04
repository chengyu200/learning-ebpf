/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 53-fsession: BPF_TRACE_FSESSION 函数延迟测量。
 *
 * 共享定义：BPF 和用户态共用。
 */
#ifndef __FSESSION_H
#define __FSESSION_H

#define TASK_COMM_LEN 16
#define MAX_SLOTS 27  /* log2 直方图桶数 */

/* 内核→用户态的事件结构 */
struct event {
	__u32 pid;
	__u64 latency_ns;     /* 函数延迟（纳秒） */
	char comm[TASK_COMM_LEN];
};

#endif /* __FSESSION_H */
