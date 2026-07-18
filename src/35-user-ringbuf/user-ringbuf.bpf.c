// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 35-user-ringbuf: asynchronously send messages from user space to kernel.
 *
 * User space writes into a BPF_MAP_TYPE_USER_RINGBUF; a BPF program (triggered
 * by a timer via perf_event) drains it with bpf_user_ringbuf_drain and prints
 * each received message.  Demonstrates the user-ringbuf map type.
 *
 * 教学概念：
 * - BPF_MAP_TYPE_USER_RINGBUF：用户态→内核态的环形缓冲区
 * - bpf_user_ringbuf_drain：内核侧排空 helper
 * - perf_event 程序作为定期触发器
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} user_ring SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* bpf_user_ringbuf_drain 的回调函数 */
static int handle_msg(void *ctx, void *data, size_t len)
{
	bpf_printk("user-ringbuf: received %u bytes", (__u32)len);
	return 0;
}

SEC("perf_event")
int drain_user_ring(void *ctx)
{
	long ret = bpf_user_ringbuf_drain(&user_ring, handle_msg, NULL, 0);
	if (ret > 0)
		bpf_printk("drain: drained %ld records", ret);
	return 0;
}
