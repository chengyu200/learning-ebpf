// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 7-execsnoop: capture process execution, output via perf event array.
 *
 * Kernel side: hook the sched_process_exec tracepoint and send {pid, ppid,
 * comm, filename} to user space with a BPF_MAP_TYPE_PERF_EVENT_ARRAY and
 * bpf_perf_event_output().  This is the classic perf-buffer path.
 * Teaches: perf event array maps, bpf_perf_event_output, reading a
 * __data_loc tracepoint field.  Contrast the user-space perf_buffer API with
 * the ring_buffer API used in 8-exitsnoop.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned fname_off;
	struct event e = {};
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;

	e.pid = pid;
	e.ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	/* __data_loc_filename encodes the offset (low 16 bits) into the
	 * tracepoint payload where the filename string lives. */
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(&e.filename, sizeof(e.filename),
				  (void *)ctx + fname_off);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}
