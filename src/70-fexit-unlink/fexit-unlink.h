/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 70-fexit-unlink: 用 fexit 追踪文件删除结果（成功/失败）。
 *
 * 共享定义：事件结构体。
 */
#ifndef __FEXIT_UNLINK_H
#define __FEXIT_UNLINK_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	unsigned int uid;
	int ret;		/* vfs_unlink 返回值：0=成功，负数=错误码 */
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

#endif /* __FEXIT_UNLINK_H */
