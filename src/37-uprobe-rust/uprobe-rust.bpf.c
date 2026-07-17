// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 37-uprobe-rust: trace slow_function() in a Rust program via uprobe. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "uprobe-rust.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe")
int BPF_KPROBE(trace_slow_function, u64 x)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ts_ns = bpf_ktime_get_ns();
	e->arg = x;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
