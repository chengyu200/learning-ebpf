// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 75-kprobe-multi: 多函数 kprobe 追踪。
 *
 * 三个程序展示 kprobe.multi / kretprobe.multi / kprobe.session：
 *
 * ① kprobe.multi/vfs_*   — 一次匹配所有 vfs_* 函数入口
 * ② kretprobe.multi/vfs_* — 一次匹配所有 vfs_* 函数返回
 * ③ kprobe.session/vfs_read — 入口+返回合一，测量 vfs_read 延迟
 *
 * 对比传统 kprobe（2-kprobe-unlink）：
 *   传统：一个函数需要一个 SEC("kprobe/func")，70 个函数需要 70 个程序
 *   multi：一个 SEC("kprobe.multi/vfs_*") 匹配所有 vfs_* 函数
 *
 * 对比 fsession（64-fsession）：
 *   fsession：基于 fentry/fexit trampoline，需要 BTF
 *   kprobe.session：基于 kprobe int3，不需要 BTF，任意内核函数可用
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "kpmulti.h"

char LICENSE[] SEC("license") = "GPL";

/* 用户态设置自身 PID，过滤自身产生的 vfs_* 调用（避免反馈循环） */
const volatile __u32 self_pid = 0;

/* 用户态设置目标 PID：只追踪该进程的 VFS 调用（0=全部，但排除 self_pid） */
const volatile __u32 target_pid = 0;

#define PID_FILTER()                                              \
	do {                                                      \
		__u32 _pid = bpf_get_current_pid_tgid() >> 32;    \
		if (self_pid && _pid == self_pid)                  \
			return 0;                                 \
		if (target_pid && _pid != target_pid)              \
			return 0;                                 \
	} while (0)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* kprobe.session 的 kfunc 声明（同 fsession） */
extern bool bpf_session_is_return(void *ctx) __weak __ksym;
extern __u64 *bpf_session_cookie(void *ctx) __weak __ksym;

/* ① kprobe.multi/vfs_* — 多函数入口探针
 *
 * 一个程序匹配所有 vfs_* 内核函数（约 70 个）。
 * bpf_get_func_ip(ctx) 返回被探测函数的地址，
 * 用户态通过 /proc/kallsyms 解析为函数名。 */
SEC("kprobe.multi/vfs_*")
int BPF_KPROBE(handle_entry)
{
	struct event *e;
	__u32 pid;

	PID_FILTER();

	pid = bpf_get_current_pid_tgid() >> 32;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_ENTRY;
	e->pid = pid;
	e->ip = bpf_get_func_ip(ctx);
	e->latency_ns = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ② kretprobe.multi/vfs_* — 多函数返回探针 */
SEC("kretprobe.multi/vfs_*")
int BPF_KRETPROBE(handle_return)
{
	struct event *e;
	__u32 pid;

	PID_FILTER();

	pid = bpf_get_current_pid_tgid() >> 32;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_RETURN;
	e->pid = pid;
	e->ip = bpf_get_func_ip(ctx);
	e->latency_ns = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ③ kprobe.session/vfs_read — 入口+返回合一，测量延迟
 *
 * kprobe.session 是 kprobe 版本的 fsession：
 *   - 一个程序在入口和返回都执行
 *   - bpf_session_is_return(ctx) 区分入口/返回
 *   - bpf_session_cookie(ctx) 提供 per-call 私有存储
 *   - 不需要 BTF（与 fsession 的关键区别）
 *
 * 返回值语义（与 fsession 相反！）：
 *   入口返回 0 = 继续执行返回阶段
 *   入口返回非 0 = 跳过返回阶段
 * （fsession 是 0=跳过, 非0=继续，kprobe.session 正好相反） */
SEC("kprobe.session/vfs_read")
int BPF_KPROBE(handle_session)
{
	bool is_return;
	__u64 *cookie;
	__u32 pid;
	struct event *e;

	is_return = bpf_session_is_return(ctx);
	cookie = bpf_session_cookie(ctx);
	pid = bpf_get_current_pid_tgid() >> 32;

	if (self_pid && pid == self_pid)
		return 0;
	if (target_pid && pid != target_pid)
		return 0;

	if (!cookie)
		return 0;

	if (!is_return) {
		/* 入口：存时间戳 */
		*cookie = bpf_ktime_get_ns();
		return 0;  /* kprobe.session: return 0 = 继续执行返回阶段 */	}

	/* 返回：计算延迟 */
	__u64 ts = *cookie;
	if (ts == 0)
		return 0;

	__u64 delta = bpf_ktime_get_ns() - ts;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_LATENCY;
	e->pid = pid;
	e->ip = bpf_get_func_ip(ctx);
	e->latency_ns = delta;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
