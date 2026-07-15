// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 9-runqlat: capture run-queue latency and record it as a log2 histogram.
 *
 * Kernel side: on sched_wakeup (a task becomes runnable) record the timestamp
 * keyed by pid in a hash; on sched_switch, when next_pid is a task we recorded,
 * compute the latency (now - wakeup time), bucket it into a log2 slot, and bump
 * a counter in an array map.  User space polls the array and prints the
 * histogram.
 * Teaches: BPF_MAP_TYPE_ARRAY, log2 bucketing (using __builtin_clzll), polling
 * a map from user space (no ring/perf output).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "runqlat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);            /* pid */
	__type(value, u64);          /* wakeup timestamp (ns) */
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SLOTS);
	__type(key, u32);            /* slot index */
	__type(value, u64);          /* count */
} hist SEC(".maps");

SEC("tp/sched/sched_wakeup")
int handle_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	u32 pid = ctx->pid;
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
	return 0;
}

SEC("tp/sched/sched_wakeup_new")
int handle_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
	u32 pid = ctx->pid;
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
	return 0;
}

SEC("tp/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
	u32 next_pid = ctx->next_pid;
	u64 *tsp, now, delta_us, slot;
	u64 one = 1, *cnt;

	tsp = bpf_map_lookup_elem(&start, &next_pid);
	if (!tsp)
		return 0;

	now = bpf_ktime_get_ns();
	delta_us = (now - *tsp) / 1000;  /* nanoseconds -> microseconds */
	bpf_map_delete_elem(&start, &next_pid);

	/* log2 histogram slot for the latency in microseconds */
	if (delta_us == 0)
		slot = 0;
	else
		slot = 64 - __builtin_clzll(delta_us);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	cnt = bpf_map_lookup_elem(&hist, &slot);
	if (cnt)
		*cnt += 1;
	else
		bpf_map_update_elem(&hist, &slot, &one, BPF_NOEXIST);
	return 0;
}
