// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 84-iter-memcg: 内核态 BPF 程序 — 遍历所有 mem_cgroup。
 *
 * 使用 open-coded iterator（bpf_for_each(css, ...)）遍历 mem_cgroup 树：
 *   1. bpf_get_root_mem_cgroup() 获取 root mem_cgroup（__ksym）
 *   2. bpf_for_each(css, ...) 遍历 root 的 css 子树
 *   3. container_of(css, mem_cgroup, css) 获取 mem_cgroup
 *   4. 读取 memory.usage / swap.usage / cgroup 路径名
 *   5. 发送 ringbuf 事件
 *
 * 触发方式：tracepoint sys_enter_openat + PID 过滤
 *
 * 教学概念：
 * - bpf_get_root_mem_cgroup()：获取 root mem_cgroup（__ksym kfunc）
 * - bpf_for_each(css, ...)：open-coded iterator 遍历 css 子树
 * - bpf_iter_css_new/next/destroy：底层 kfuncs（由 bpf_for_each 封装）
 * - container_of(css, mem_cgroup, css)：从 css 获取 mem_cgroup
 * - BPF_CORE_READ：安全读取内核结构体字段
 * - mem_cgroup->memory.usage：atomic_long_t 内存使用量
 * - css->cgroup->kn->name：cgroup 路径名
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "iter-memcg.h"

char LICENSE[] SEC("license") = "GPL";

/* kfunc 声明 */
extern struct mem_cgroup *bpf_get_root_mem_cgroup(void) __ksym;
extern void bpf_put_mem_cgroup(struct mem_cgroup *memcg) __ksym;

/* open-coded css iterator kfuncs（由 bpf_for_each(css, ...) 宏调用） */
extern void bpf_iter_css_destroy(struct bpf_iter_css *it) __ksym;
extern int bpf_iter_css_new(struct bpf_iter_css *it,
			    struct cgroup_subsys_state *start,
			    unsigned int flags) __ksym;
extern struct cgroup_subsys_state *bpf_iter_css_next(struct bpf_iter_css *it) __ksym;

/* 用户态设置：0=禁用，非0=仅该 PID 触发 */
pid_t target_pid = 0;

/* BPF_CGROUP_ITER_ORDER_* flags for bpf_iter_css_new */
#define BPF_CGROUP_ITER_SELF_ONLY       1
#define BPF_CGROUP_ITER_DESCENDANTS_PRE  2
#define BPF_CGROUP_ITER_DESCENDANTS_POST 3
#define BPF_CGROUP_ITER_ANCESTORS_UP     4
#define BPF_CGROUP_ITER_CHILDREN         5

/* ringbuf：事件通道 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int dump_memcgs(void *ctx)
{
	struct mem_cgroup *root;
	struct cgroup_subsys_state *css;

	if (target_pid == 0)
		return 0;
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	root = bpf_get_root_mem_cgroup();
	if (!root)
		return 0;

	/* bpf_for_each(css, ...) 遍历 root mem_cgroup 的 css 子树
	 * flags=BPF_CGROUP_ITER_DESCENDANTS_PRE 表示前序遍历所有后代（包括自身） */
	bpf_for_each(css, css, &root->css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		struct memcg_event *e;
		struct mem_cgroup *memcg;
		struct cgroup *cg;
		struct kernfs_node *kn;

		/* container_of：css 是 mem_cgroup 的第一个字段 */
		memcg = container_of(css, struct mem_cgroup, css);

		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (!e)
			continue;

		e->pid = target_pid;

		/* 读取 mem_cgroup ID */
		e->memcg_id = BPF_CORE_READ(memcg, css.serial_nr);

		/* 读取内存使用量（page_counter->usage，atomic_long_t） */
		e->memory_usage = BPF_CORE_READ(memcg, memory.usage.counter);

		/* 读取 swap 使用量 */
		e->swap_usage = BPF_CORE_READ(memcg, swap.usage.counter);

		/* 读取 cgroup 路径名 */
		cg = BPF_CORE_READ(css, cgroup);
		if (cg) {
			kn = BPF_CORE_READ(cg, kn);
			if (kn) {
				e->level = BPF_CORE_READ(cg, level);
				bpf_probe_read_kernel_str(e->cgroup_name,
							  sizeof(e->cgroup_name),
							  BPF_CORE_READ(kn, name));
			}
		}

		bpf_ringbuf_submit(e, 0);
	}

	/* 释放 bpf_get_root_mem_cgroup 获取的引用 */
	bpf_put_mem_cgroup(root);

	return 0;
}
