/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BASHREADLINE_H
#define __BASHREADLINE_H

#define TASK_COMM_LEN 16
#define MAX_LINE_LEN 256

struct event {
	int pid;
	char comm[TASK_COMM_LEN];
	char line[MAX_LINE_LEN];
};

#endif /* __BASHREADLINE_H */
