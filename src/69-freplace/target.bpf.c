// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 69-freplace: 目标 BPF 程序 — 进程执行追踪器。
 *
 * 包含一个可被 freplace 替换的全局函数 filter_check()：
 *   原始逻辑：记录所有进程（return 1）
 *   被替换后：只记录 PID 为偶数 的进程（由 ext.bpf.c 实现）
 *
 * filter_check 使用 __attribute__((noinline)) + volatile 防止内联。
 * 编译时需加 -mllvm -inline-threshold=0（见 Makefile）。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "freplace.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* 可被 freplace 替换的过滤函数。
 * __attribute__((noinline)) + volatile 阻止编译器内联，
 * 确保函数作为独立 subprogram 存在（freplace 的前提）。
 * 返回 1=记录该进程，0=过滤掉。 */
__attribute__((noinline))
int filter_check(__u32 pid)
{
	volatile int r = pid > 0 ? 1 : 0;
	return r;
}

SEC("tp/sched/sched_process_exec")
int target_prog(void *ctx)
{
	struct exec_event *e;
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	e->filtered = !filter_check(pid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
