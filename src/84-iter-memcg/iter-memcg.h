/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 84-iter-memcg: 共享定义。
 */
#ifndef __ITER_MEMCG_H
#define __ITER_MEMCG_H

#define CGROUP_NAME_LEN 128

/* ringbuf 事件：每个 mem_cgroup 一条 */
struct memcg_event {
	__u64 memcg_id;		/* mem_cgroup ID */
	__u64 memory_usage;	/* 内存使用量（字节） */
	__u64 swap_usage;	/* swap 使用量（字节） */
	__u32 pid;		/* 触发遍历的 PID */
	__u32 level;		/* cgroup 层级深度 */
	char  cgroup_name[CGROUP_NAME_LEN];  /* cgroup 路径名 */
};

#endif /* __ITER_MEMCG_H */
