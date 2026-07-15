// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 16-memleak (simplified): trace outstanding userspace allocations.
 *
 * Hooks libc malloc/calloc/realloc (uprobe+uretprobe) and free (uprobe) in the
 * target object, records each outstanding allocation keyed by its address along
 * with a user-space stack id, and lets the user-space loader report the top
 * outstanding stacks.  Kernel kmem tracepoints and combined-allocs aggregation
 * from the full libbpf-tools memleak are intentionally omitted here.
 * Teaches: uprobe/uretprobe on libc, BPF_MAP_TYPE_STACK_TRACE, walking a hash
 * map of live allocations from user space.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "memleak.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;
const volatile __u64 sample_rate = 1;
const volatile __u64 stack_flags = BPF_F_USER_STACK;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct alloc_info);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 10240);
	__type(key, u32);
} stack_traces SEC(".maps");

static __always_inline int gen_alloc_enter(size_t size)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts;

	if (target_pid && target_pid != pid)
		return 0;
	if (sample_rate > 1) {
		ts = bpf_ktime_get_ns();
		if (ts % sample_rate != 0)
			return 0;
	}
	bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);
	return 0;
}

static __always_inline int gen_alloc_exit(void *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u64 *sizep, address;
	struct alloc_info info = {};

	sizep = bpf_map_lookup_elem(&sizes, &pid);
	if (!sizep)
		return 0;
	info.size = *sizep;
	bpf_map_delete_elem(&sizes, &pid);

	address = (u64)PT_REGS_RC(ctx);
	if (address == 0)
		return 0;

	info.timestamp_ns = bpf_ktime_get_ns();
	info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);
	bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);
	return 0;
}

static __always_inline int gen_free_enter(const void *address)
{
	u64 addr = (u64)address;

	bpf_map_delete_elem(&allocs, &addr);
	return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size) { return gen_alloc_enter(size); }

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter(ptr);
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(realloc_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address) { return gen_free_enter(address); }
