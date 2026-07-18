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
 * - 回调签名是 (struct bpf_dynptr *dynptr, void *context)，
 *   数据通过 bpf_dynptr_read 或 bpf_dynptr_data 读取
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

/* bpf_user_ringbuf_drain 的回调函数
 *
 * 注意：回调签名是 (struct bpf_dynptr *dynptr, void *context)，
 * 不是 (void *ctx, void *data, size_t len)。
 * 数据需要通过 bpf_dynptr_read 或 bpf_dynptr_data 从 dynptr 读取。
 *
 * @dynptr   包含用户态写入数据的动态指针
 * @context  透传的用户上下文
 * @return   0=继续排空，非0=停止 */
static long handle_msg(struct bpf_dynptr *dynptr, void *context)
{
	char buf[8] = {};

	/* 用 bpf_dynptr_read 从 dynptr 读取前 8 字节到栈缓冲区 */
	int ret = bpf_dynptr_read(buf, sizeof(buf), dynptr, 0, 0);
	if (ret == 0)
		bpf_printk("user-ringbuf: recv: %c%c%c%c%c%c%c%c",
			   buf[0], buf[1], buf[2], buf[3],
			   buf[4], buf[5], buf[6], buf[7]);
	else
		bpf_printk("user-ringbuf: dynptr_read failed: %d", ret);

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
