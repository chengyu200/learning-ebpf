// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* features/bpf_arena: arena 地址空间演示。
 *
 * arena map 允许 BPF 程序和用户态共享内存区域（零拷贝）。
 * BPF 程序用 bpf_arena_alloc_pages kfunc 分配页面，然后直接读写。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 10);
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32);
#else
	__ulong(map_extra, 0x1ull << 44);
#endif
} arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

extern void __attribute__((address_space(1)))
*bpf_arena_alloc_pages(void *map,
		       void __attribute__((address_space(1))) *addr,
		       __u32 page_cnt, int node_id, __u64 flags) __ksym;

/* 保存已分配的 arena 页面地址（0 = 未分配） */
static __u64 arena_page_addr = 0;

SEC("tp/syscalls/sys_enter_execve")
int arena_demo(void *ctx)
{
	/* 只在第一次调用时分配 arena 页面 */
	if (arena_page_addr == 0) {
		void __attribute__((address_space(1))) *page =
			bpf_arena_alloc_pages(&arena, NULL, 1, -1, 0);
		if (!page)
			return 0;
		arena_page_addr = (__u64)(unsigned long)page;
	}

	if (arena_page_addr == 0)
		return 0;

	/* 通过 arena 指针递增计数器 */
	__u64 __attribute__((address_space(1))) *cnt =
		(__u64 __attribute__((address_space(1))) *)arena_page_addr;
	*cnt = *cnt + 1;

	/* 通过 ringbuf 发送当前值 */
	__u64 *val = bpf_ringbuf_reserve(&rb, sizeof(*val), 0);
	if (val) {
		*val = *cnt;
		bpf_ringbuf_submit(val, 0);
	}
	return 0;
}
