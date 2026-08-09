/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 74-uprobe-multi-session: 共享定义。
 */
#ifndef __UPROBE_MULTI_H
#define __UPROBE_MULTI_H

#define TASK_COMM_LEN 16

/* cookie 值：区分 uprobe.multi / uretprobe.multi 中被触发的函数 */
#define FUNC_A 1
#define FUNC_B 2

/* 事件类型 */
enum event_type {
	EVENT_ENTRY   = 1,	/* uprobe.multi: 函数入口 */
	EVENT_RETURN  = 2,	/* uretprobe.multi: 函数返回 */
	EVENT_SESSION = 3,	/* uprobe.session: 函数延迟 */
};

/* ringbuf 事件结构 */
struct event {
	__u32 type;		/* enum event_type */
	__u32 func_id;		/* FUNC_A / FUNC_B (entry/return) 或 0 (session) */
	__u32 pid;
	__u32 arg;		/* 函数入口参数（entry 事件） */
	__u64 latency_ns;	/* 函数延迟（session 事件） */
	char comm[TASK_COMM_LEN];
};

#endif /* __UPROBE_MULTI_H */
