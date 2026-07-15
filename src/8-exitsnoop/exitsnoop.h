/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXITSNOOP_H
#define __EXITSNOOP_H

#define TASK_COMM_LEN 16

struct event {
	int pid;
	int ppid;
	int exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
};

#endif /* __EXITSNOOP_H */
