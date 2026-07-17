// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 39-nginx: trace nginx request handling via uprobe on ngx_http_process_request.
 * Entry records a timestamp; uretprobe computes duration and sends to ringbuf.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nginx.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe")
int BPF_KPROBE(ngx_process_entry)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &pid, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(ngx_process_ret)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 *tsp, now, dur;
	struct event *e;

	tsp = bpf_map_lookup_elem(&starts, &pid);
	if (!tsp)
		return 0;
	now = bpf_ktime_get_ns();
	dur = now - *tsp;
	bpf_map_delete_elem(&starts, &pid);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = pid;
	e->ts_ns = now;
	e->duration_ns = dur;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
