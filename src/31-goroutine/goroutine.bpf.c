// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 31-goroutine: count goroutine creations via uprobe on runtime.newproc.
 * Each call to runtime.newproc (go statement) is captured; the BPF program
 * records pid + timestamp and sends to user space via ringbuf.
 * Teaches: uprobe on Go runtime symbols, tracing goroutine lifecycle.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct event {
	__u32 pid;
	__u64 ts_ns;
};

SEC("uprobe")
int BPF_KPROBE(trace_newproc)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ts_ns = bpf_ktime_get_ns();
	bpf_ringbuf_submit(e, 0);
	return 0;
}
