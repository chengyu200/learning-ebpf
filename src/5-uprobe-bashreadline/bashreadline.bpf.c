// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 5-uprobe-bashreadline: capture commands typed into bash via uretprobe.
 *
 * Kernel side: a uretprobe on /bin/bash:readline() fires after readline returns
 * the line the user entered.  We read that returned string and push it to user
 * space through a ring buffer, along with pid/comm.
 * Teaches: uprobe/uretprobe attachment, reading a function return value with
 * BPF_KRETPROBE, bpf_probe_read_user_str, ring buffer output.
 *
 * Note: if your bash does not export a readline symbol, attach to libreadline
 * instead (see README.md) by changing the SEC() target below.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bashreadline.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const char *str)
{
	struct event *e;
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	/* str is the value returned by readline(): the typed line. */
	bpf_probe_read_user_str(&e->line, sizeof(e->line), str);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
