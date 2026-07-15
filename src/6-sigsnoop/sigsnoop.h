/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SIGSNOOP_H
#define __SIGSNOOP_H

#define TASK_COMM_LEN 16

struct event {
	int pid;       /* sender pid */
	int tpid;      /* target pid */
	int sig;
	int ret;       /* return value of the kill syscall */
	char comm[TASK_COMM_LEN];
};

#endif /* __SIGSNOOP_H */
