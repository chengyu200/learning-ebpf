// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 8-exitsnoop: monitor process exit events, output via ring buffer.
 *
 * Kernel side: record a start timestamp on sched_process_fork keyed by pid;
 * on sched_process_exit (process, not thread) compute the lifetime, read the
 * exit code and parent pid from the task_struct, and push an event to user space
 * through a BPF_MAP_TYPE_RINGBUF.  This is the modern ring-buffer path.
 * Teaches: ring buffer maps (bpf_ringbuf_reserve/submit), fork+exit tracking
 * with a hash map, reading task_struct fields with BPF_CORE_READ.  Contrast the
 * user-space ring_buffer API with the perf_buffer API used in 7-execsnoop.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	pid_t child_pid = ctx->child_pid;

	bpf_map_update_elem(&start, &child_pid, &ts, BPF_ANY);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	pid_t tid = (u32)id;
	u64 *start_ts, duration_ns = 0;
	struct task_struct *task;
	struct event *e;

	/* Ignore thread exits; only report whole-process termination. */
	if (pid != tid)
		return 0;

	start_ts = bpf_map_lookup_elem(&start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	bpf_map_delete_elem(&start, &pid);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	e->duration_ns = duration_ns;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
