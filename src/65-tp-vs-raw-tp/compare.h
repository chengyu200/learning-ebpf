/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 65-tp-vs-raw-tp: Tracepoint vs Raw Tracepoint 对比示例。
 *
 * 共享定义：BPF 和用户态共用。
 */
#ifndef __COMPARE_H
#define __COMPARE_H

#define TASK_COMM_LEN 16

/* per-CPU 统计数据（两种程序各一份） */
struct stats {
	__u64 count;        /* 事件触发次数 */
	__u64 total_ns;     /* 累计执行时间（纳秒） */
};

#endif /* __COMPARE_H */
