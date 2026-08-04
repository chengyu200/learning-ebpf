/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 63-tp-btf: tp_btf (BTF-based raw tracepoint) 示例共享定义。
 */
#ifndef __TP_BTF_H
#define __TP_BTF_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#define EVENT_EXEC  1
#define EVENT_FORK  2
#define EVENT_EXIT  3

struct event {
	__u8 type;           /* EVENT_EXEC / EVENT_FORK / EVENT_EXIT */
	__u8 pad[3];
	__s32 pid;
	__s32 ppid;
	__u32 exit_code;     /* 仅 EXIT 有效 */
	__u64 ts_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];  /* 仅 EXEC 有效 */
};

#endif /* __TP_BTF_H */
