/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROFILE_H
#define __PROFILE_H

#define MAX_STACK_DEPTH 127
#define TASK_COMM_LEN 16

struct stacktrace_event {
	int pid;
	int cpu_id;
	unsigned long long timestamp;
	char comm[TASK_COMM_LEN];
	int kstack_sz; /* in bytes */
	int ustack_sz; /* in bytes */
	unsigned long long kstack[MAX_STACK_DEPTH];
	unsigned long long ustack[MAX_STACK_DEPTH];
};

#endif /* __PROFILE_H */
