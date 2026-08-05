/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 69-freplace: BPF 程序运行时热补丁共享定义。
 */
#ifndef __FREPLACE_H
#define __FREPLACE_H

#define TASK_COMM_LEN 16

struct exec_event {
	__u32 pid;
	__u32 filtered;  /* 1=被过滤掉, 0=通过 */
	char comm[TASK_COMM_LEN];
};

#endif /* __FREPLACE_H */
