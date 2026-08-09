// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 74-uprobe-multi-session: 内核态 BPF 程序。
 *
 * 演示三种 uprobe SEC 类型，全部基于 BPF_PROG_TYPE_KPROBE：
 *
 *   1. SEC("uprobe.multi")    — 一个程序 attach 到多个函数入口
 *      attach_type = BPF_TRACE_UPROBE_MULTI
 *      通过 bpf_get_attach_cookie(ctx) 区分是哪个函数
 *
 *   2. SEC("uretprobe.multi") — 一个程序 attach 到多个函数返回
 *      attach_type = BPF_TRACE_UPROBE_MULTI (retprobe=true)
 *      同样通过 cookie 区分函数
 *
 *   3. SEC("uprobe.session")  — 一个程序在函数入口和返回都运行
 *      attach_type = BPF_TRACE_UPROBE_SESSION
 *      通过 bpf_session_is_return(ctx) 判断阶段
 *      通过 bpf_session_cookie(ctx) 在入口/返回间共享数据
 *
 * 三种类型的对比：
 *
 *   传统 uprobe:     1 函数 = 1 程序（入口），需要 N 个程序监控 N 个函数
 *   uprobe.multi:    N 函数 = 1 程序（入口），用 cookie 区分
 *   uretprobe.multi: N 函数 = 1 程序（返回），用 cookie 区分
 *   uprobe.session:  1 函数 = 1 程序（入口+返回），用 session cookie 传数据
 *
 * 目标函数在用户态加载器中定义：work_a, work_b, work_c
 * 手动 attach（非 SEC 自动 attach），使用 bpf_program__attach_uprobe_multi() API
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe-multi-session.h"

char LICENSE[] SEC("license") = "GPL";

/* session cookie kfunc 声明（与 fsession 相同的 kfunc） */
extern bool bpf_session_is_return(void *ctx) __ksym;
extern __u64 *bpf_session_cookie(void *ctx) __ksym;

/* ringbuf：内核→用户态事件通道 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ── 程序 1: uprobe.multi — 多函数入口 ──
 *
 * 手动 attach 到 work_a + work_b（cookie 分别为 FUNC_A, FUNC_B）
 * 读取第一个参数 (int n)，发送 ENTRY 事件
 */
SEC("uprobe.multi")
int uprobe_multi_entry(struct pt_regs *ctx)
{
	__u64 cookie = bpf_get_attach_cookie(ctx);
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type    = EVENT_ENTRY;
	e->func_id = (__u32)cookie;
	e->pid     = bpf_get_current_pid_tgid() >> 32;
	e->arg     = (__u32)PT_REGS_PARM1(ctx);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 程序 2: uretprobe.multi — 多函数返回 ──
 *
 * 手动 attach 到 work_a + work_b（retprobe=true，cookie 同上）
 * 发送 RETURN 事件
 */
SEC("uretprobe.multi")
int uprobe_multi_return(struct pt_regs *ctx)
{
	__u64 cookie = bpf_get_attach_cookie(ctx);
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type    = EVENT_RETURN;
	e->func_id = (__u32)cookie;
	e->pid     = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 程序 3: uprobe.session — 入口+返回一体 ──
 *
 * 手动 attach 到 work_c（session=true）
 * 入口: bpf_session_is_return()=false → 存时间戳到 session cookie
 * 返回: bpf_session_is_return()=true  → 读时间戳，算延迟，发 SESSION 事件
 *
 * 与传统 uprobe+uretprobe 对比：
 *   传统: 2 个 BPF 程序 + BPF_MAP_TYPE_HASH 按 tid 传时间戳
 *   session: 1 个 BPF 程序 + session cookie（内核内置，无需 map）
 */
SEC("uprobe.session")
int uprobe_session_prog(struct pt_regs *ctx)
{
	bool is_return;
	__u64 *cookie;
	__u64 ts;

	is_return = bpf_session_is_return(ctx);
	cookie = bpf_session_cookie(ctx);

	if (!cookie)
		return 0;

	if (!is_return) {
		/* ── 入口阶段：存储时间戳 ── */
		*cookie = bpf_ktime_get_ns();
	} else {
		/* ── 返回阶段：计算延迟 ── */
		ts = *cookie;
		if (ts == 0)
			return 0;

		__u64 delta = bpf_ktime_get_ns() - ts;

		struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (e) {
			e->type       = EVENT_SESSION;
			e->func_id    = 0;
			e->pid        = bpf_get_current_pid_tgid() >> 32;
			e->latency_ns = delta;
			bpf_get_current_comm(&e->comm, sizeof(e->comm));
			bpf_ringbuf_submit(e, 0);
		}
	}

	return 0;
}
