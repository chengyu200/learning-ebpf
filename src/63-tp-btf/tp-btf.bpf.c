// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 63-tp-btf: BPF 内核态 — tp_btf (BTF-based raw tracepoint)。
 *
 * tp_btf 是现代 BPF tracepoint 挂载方式：
 *   - 程序类型为 TRACING (BPF_TRACE_RAW_TP)，而非传统 TRACEPOINT
 *   - 参数通过 BPF_PROG 宏以内核函数签名形式直接提供（类型安全）
 *   - 无需从 trace_event_raw_* 结构体手动解析 __data_loc 字段
 *   - 性能与 raw_tracepoint 相同（无 trace_event 格式化开销）
 *
 * 对比 11-bootstrap 的 SEC("tp/sched/sched_process_exec")：
 *   tp/  方式：ctx->__data_loc_filename & 0xFFFF → bpf_probe_read_kernel_str
 *   tp_btf 方式：BPF_CORE_READ(bprm, filename) → bpf_probe_read_kernel_str（直接访问参数）
 *
 * 三个程序追踪进程生命周期：exec / fork / exit
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tp-btf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* 程序 1：tp_btf/sched_process_exec
 *
 * 内核 tracepoint 签名：sched_process_exec(task, old_pid, bprm)
 * BPF_PROG 宏直接提供类型化参数，无需手动解析 __data_loc_filename */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec, struct task_struct *task, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct event *e;
	const char *filename;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_EXEC;
	e->pid = BPF_CORE_READ(task, pid);
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->ts_ns = bpf_ktime_get_ns();
	e->exit_code = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* tp_btf 优势：bprm 是类型化参数，直接读取 filename */
	filename = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* 程序 2：tp_btf/sched_process_fork
 *
 * 内核 tracepoint 签名：sched_process_fork(parent, child)
 * 对比 tp/ 方式：需从 ctx->__data_loc_child_comm 解析 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork, struct task_struct *parent,
	     struct task_struct *child)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_FORK;
	e->pid = BPF_CORE_READ(child, pid);
	e->ppid = BPF_CORE_READ(parent, tgid);
	e->ts_ns = bpf_ktime_get_ns();
	e->exit_code = 0;
	e->filename[0] = '\0';

	/* 直接读取 child 的 comm */
	bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm),
				  BPF_CORE_READ(child, comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* 程序 3：tp_btf/sched_process_exit
 *
 * 内核 tracepoint 签名：sched_process_exit(task)
 * 对比 tp/ 方式：ctx->pid / ctx->comm */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *task)
{
	struct event *e;
	pid_t pid, tid;

	/* 仅处理进程退出（非线程） */
	pid = BPF_CORE_READ(task, tgid);
	tid = BPF_CORE_READ(task, pid);
	if (pid != tid)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_EXIT;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->ts_ns = bpf_ktime_get_ns();
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	e->filename[0] = '\0';
	bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm),
				  BPF_CORE_READ(task, comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
