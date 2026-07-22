/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 51-cgroup-sysctl: 监控 /proc/sys/net/ 下的 sysctl 写入。
 *
 * 参考了 systemd 的 sysctl-monitor.bpf.c 实现（commit 6d9ef22），
 * 简化了过滤逻辑，保留核心教学概念。
 *
 * 事件结构：内核态和用户态共用。
 */
#ifndef __SYSCTL_MONITOR_H
#define __SYSCTL_MONITOR_H

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 100
#define MAX_VAL_LEN 64

/* 内核→用户态的事件结构 */
struct sysctl_write_event {
	__u32 pid;                    /* 写入 sysctl 的进程 PID */
	__u64 cgroup_id;              /* 进程的 cgroup ID */
	char comm[TASK_COMM_LEN];     /* 进程名 */
	char path[MAX_PATH_LEN];      /* sysctl 路径，如 "net/ipv4/ip_forward" */
	char old_value[MAX_VAL_LEN];  /* 修改前的值 */
	char new_value[MAX_VAL_LEN];  /* 修改后的值 */
};

#endif /* __SYSCTL_MONITOR_H */
