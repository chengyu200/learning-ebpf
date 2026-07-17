// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* features/bpf_wq: BPF workqueues for asynchronous, sleepable tasks.
 *
 * Demonstrates the bpf_wq map type and the concept of scheduling deferred
 * work.  The actual bpf_wq_start/set_callback helpers are only available on
 * newer kernels (6.10+) with CONFIG_BPF_WQ; on older kernels this program
 * serves as a compile-time reference.  See:
 *   https://docs.kernel.org/bpf/bpf_wq.html
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* A bpf_wq entry in an array map; the user-space or a tracepoint triggers it. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);  /* placeholder; real type is struct bpf_wq */
} wq_map SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int wq_demo(void *ctx)
{
	__u32 key = 0;
	__u64 *cnt = bpf_map_lookup_elem(&wq_map, &key);
	if (cnt)
		*cnt += 1;
	/* In a full wq demo we'd call:
	 *   bpf_wq_init(wq, &wq_map, 0);
	 *   bpf_wq_set_callback(wq, callback, 0);
	 *   bpf_wq_start(wq, 0);
	 * These helpers require a kernel with CONFIG_BPF_WQ. */
	bpf_printk("wq: trigger count=%llu", cnt ? *cnt : 0);
	return 0;
}

