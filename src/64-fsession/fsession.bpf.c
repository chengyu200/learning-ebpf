// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-fsession: 内核态 BPF 程序 — 用 BPF_TRACE_FSESSION 测量函数延迟。
 *
 * FSESSION = Function Session：一个 BPF 程序同时在目标函数的
 * 入口（fentry）和出口（fexit）执行，通过 session cookie 共享数据。
 *
 * 工作流程：
 *   1. vfs_read 入口 → BPF 程序执行，bpf_session_is_return()=false
 *      → 用 bpf_session_cookie() 存储时间戳
 *   2. vfs_read 执行
 *   3. vfs_read 出口 → 同一个 BPF 程序再次执行，bpf_session_is_return()=true
 *      → 读取时间戳，计算延迟，发送 ringbuf 事件
 *
 * 与传统方案对比：
 *   传统 fentry + fexit：需要 2 个 BPF 程序 + BPF_MAP_TYPE_HASH 按 tid 传数据
 *   FSESSION：1 个 BPF 程序 + session cookie（内核内置，无需 map）
 *
 * 教学概念：
 * - BPF_TRACE_FSESSION：fentry + fexit 合并为一个 session
 * - bpf_session_is_return：判断当前是入口还是返回阶段
 * - bpf_session_cookie：入口存数据，出口取数据（per-call 私有）
 * - SEC("fsession/vfs_read")：libbpf 自动解析为 fentry+fexit trampoline
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "fsession.h"

char LICENSE[] SEC("license") = "GPL";

/* session cookie kfunc 声明 */
extern __u64 *bpf_session_cookie(void *ctx) __ksym;
extern bool bpf_session_is_return(void *ctx) __ksym;

/* ringbuf：内核→用户态事件通道 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* log2 直方图（按延迟分布统计） */
__u64 hist[MAX_SLOTS] = {};

/*
 * fsession 主函数：在 vfs_read 入口和出口都会被调用。
 *
 * @ctx  函数上下文（入口时是 fentry ctx，出口时是 fexit ctx）
 *       FSESSION 模式下，同一个 ctx 在入口和出口共享 session cookie
 * @return 0（不影响函数执行）
 */
SEC("fsession/vfs_read")
int measure_latency(void *ctx)
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

		/* 发送事件到 ringbuf（含 pid、comm、延迟值） */
		struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (e) {
			e->pid = bpf_get_current_pid_tgid() >> 32;
			e->latency_ns = delta;
			bpf_get_current_comm(&e->comm, sizeof(e->comm));
			bpf_ringbuf_submit(e, 0);
		}

		/* 更新 log2 直方图 */
		__u64 slot;
		if (delta == 0)
			slot = 0;
		else
			slot = 64 - __builtin_clzll(delta);
		if (slot >= MAX_SLOTS)
			slot = MAX_SLOTS - 1;
		__sync_fetch_and_add(&hist[slot], 1);
	}

	return 0;
}
