// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* features/bpf_arena: zero-copy shared memory between kernel and user space.
 *
 * Demonstrates BPF_MAP_TYPE_ARENA: a BPF program reads/writes a shared page,
 * and user space mmap's the same arena for zero-copy communication.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(max_entries, 4096); /* 1 page */
	__type(key, __u32);
	__type(value, __u64);
} arena SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int arena_demo(void *ctx)
{
	__u32 key = 0;
	__u64 *val;

	val = bpf_map_lookup_elem(&arena, &key);
	if (val)
		*val += 1;
	else {
		__u64 init = 1;
		bpf_map_update_elem(&arena, &key, &init, BPF_ANY);
	}
	return 0;
}
