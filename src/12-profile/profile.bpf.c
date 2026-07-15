// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
/* 12-profile: sample stacks on a timer via perf_event, push to ringbuf. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "profile.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} events SEC(".maps");

SEC("perf_event")
int profile(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int cpu_id = bpf_get_smp_processor_id();
	struct stacktrace_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 1;

	e->pid = pid;
	e->cpu_id = cpu_id;
	e->timestamp = bpf_ktime_get_ns();

	if (bpf_get_current_comm(e->comm, sizeof(e->comm)))
		e->comm[0] = 0;

	e->kstack_sz = bpf_get_stack(ctx, e->kstack, sizeof(e->kstack), 0);
	e->ustack_sz = bpf_get_stack(ctx, e->ustack, sizeof(e->ustack),
				      BPF_F_USER_STACK);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
