// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 28-detach: demonstrate that an eBPF program can outlive its loader.
 *
 * The BPF program (a simple execve counter) is loaded and its link is pinned
 * to /sys/fs/bpf/.  When the loader exits (without destroying the link), the
 * program keeps running.  A second invocation (--status) reads the counter
 * from the pinned map; --clean unloads it.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} exec_count SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int count_exec(void *ctx)
{
	__u32 key = 0;
	__u64 *cnt = bpf_map_lookup_elem(&exec_count, &key);
	if (cnt)
		*cnt += 1;
	return 0;
}
