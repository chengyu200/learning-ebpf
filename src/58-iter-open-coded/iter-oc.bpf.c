// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 58-iter-open-coded: BPF 内核态 — open-coded iterator（bpf_for / bpf_repeat）。
 *
 * 演示三种 open-coded 循环，用 ringbuf 输出结果（非 trace_pipe）：
 *   ① bpf_for(i, 0, N)        — 数字迭代器，验证器证明 i 在 [0,N) 范围
 *   ② bpf_for + 数组填充      — 验证器自动证明数组访问范围安全
 *   ③ bpf_repeat(N)           — 执行 N 次循环（不暴露迭代变量）
 *
 * 通过 target_pid 过滤，仅响应指定进程的 syscall，避免后台噪音。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* 用户态设置目标 PID，仅该进程的 syscall 触发输出（0=禁用） */
pid_t target_pid = 0;

struct oc_event {
	__u32 pid;
	__u32 prog_id;  /* 1=sum_squares, 2=fill_array, 3=repeat */
	__u64 result;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* 程序 1：bpf_for 计算 0..9 的平方和 */
SEC("tp/syscalls/sys_enter_openat")
int sum_squares(void *ctx)
{
	__u64 sum = 0;
	int i;
	struct oc_event *e;

	if (target_pid == 0)
		return 0;
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	bpf_for(i, 0, 10) {
		sum += i * i;
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = target_pid;
	e->prog_id = 1;
	e->result = sum;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* 程序 2：bpf_for 填充数组，验证器知道 i ∈ [0,10)，无需额外边界检查 */
SEC("tp/syscalls/sys_enter_read")
int fill_array(void *ctx)
{
	__u64 arr[10] = {};
	int i;
	struct oc_event *e;

	if (target_pid == 0)
		return 0;
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	bpf_for(i, 0, 10) {
		arr[i] = i * i;
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = target_pid;
	e->prog_id = 2;
	e->result = arr[5];  /* 取 arr[5]=25 作为代表 */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* 程序 3：bpf_repeat 执行 N 次循环 */
SEC("tp/syscalls/sys_enter_write")
int repeat_demo(void *ctx)
{
	__u64 count = 0;
	struct oc_event *e;

	if (target_pid == 0)
		return 0;
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	bpf_repeat(5) {
		count++;
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = target_pid;
	e->prog_id = 3;
	e->result = count;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
