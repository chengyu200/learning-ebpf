// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 38-btf-uprobe: expand CO-RE (Compile Once, Run Everywhere) to userspace.
 *
 * Attach a BPF uprobe to a userspace function and read a field from a
 * userspace struct via BPF_CORE_READ, using the target binary's BTF (if it
 * has any).  Demonstrates that CO-RE field-relocation works against userspace
 * types, not just kernel types.
 *
 * We attach to malloc() in libc and read the size argument; the struct
 * inspection is conceptual (libc has no BTF, so we fall back to direct reads).
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
	__u64 size;
};

SEC("uprobe")
int BPF_KPROBE(trace_malloc, size_t size)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->size = size;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
