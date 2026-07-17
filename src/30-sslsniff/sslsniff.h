/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SSLSNIFF_H
#define __SSLSNIFF_H

#define MAX_DATA_SIZE 256
#define TASK_COMM_LEN 16

struct event {
	__u32 pid;
	__u64 ts_ns;
	int rw;              /* 0 = read, 1 = write */
	int data_len;
	char comm[TASK_COMM_LEN];
	char data[MAX_DATA_SIZE];
};

#endif
