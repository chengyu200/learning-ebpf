/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 72-ksyscall: 跨架构系统调用追踪共享定义。
 */
#ifndef __KSYSCALL_H
#define __KSYSCALL_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#define EVENT_ENTRY 1
#define EVENT_EXIT  2

struct event {
	__u8  type;       /* EVENT_ENTRY / EVENT_EXIT */
	__u8  pad[3];
	__s32 pid;
	__s32 ret;        /* 返回值（仅 EXIT 有效） */
	__u64 ts_ns;      /* 时间戳 */
	__u64 latency_ns; /* 延迟（仅 EXIT 有效） */
	__u32 flags;      /* openat flags（仅 ENTRY 有效） */
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN]; /* 仅 ENTRY 有效 */
};

#endif /* __KSYSCALL_H */
