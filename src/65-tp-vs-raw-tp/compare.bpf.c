// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 65-tp-vs-raw-tp: 内核态 BPF 程序。
 *
 * 两个程序挂载到同一个 tracepoint（sched/sched_switch），
 * 功能相同（统计进程切换），但写法不同：
 *
 * 程序 1: TRACEPOINT — 类型化上下文，字段已解析
 *   SEC("tp/sched/sched_switch")
 *   ctx 是 struct trace_event_raw_sched_switch *
 *   直接访问 ctx->prev_pid, ctx->next_comm 等
 *
 * 程序 2: RAW_TRACEPOINT — 原始参数，需 CO-RE 读取
 *   SEC("raw_tp/sched_switch")
 *   ctx 是 struct bpf_raw_tracepoint_args *
 *   ctx->args[0] = prev task_struct*, args[1] = next task_struct*
 *   需用 BPF_CORE_READ 从 task_struct 读取 pid/comm
 *
 * 教学概念：
 * - 两种程序类型的上下文差异
 * - TRACEPOINT：内核先格式化数据（开销），BPF 直接用字段
 * - RAW_TRACEPOINT：跳过格式化（省开销），BPF 需 CO-RE 读取
 * - 性能对比：用 bpf_ktime_get_ns 测量每个程序的平均执行时间
 * - 只计数模式：read_fields=0 时跳过字段读取，对比纯内核侧开销
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "compare.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * read_fields: 控制是否读取字段（由用户态在 load 前设置）
 *   0 = 只计数（跳过字段读取，对比纯内核侧开销）
 *   1 = 计数 + 读取字段（对比 BPF 程序内部开销，含 CO-RE）
 */
const volatile bool read_fields = true;

/* 两个 per-CPU array map，分别存储两种程序的统计 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stats);
} tp_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stats);
} raw_tp_stats SEC(".maps");

/* ── 程序 1: TRACEPOINT（类型化上下文）──
 *
 * ctx 是内核格式化后的结构体，字段名与 tracepoint format 一致。
 * 不需要 BPF_CORE_READ，直接访问字段。
 */
SEC("tp/sched/sched_switch")
int count_tp(struct trace_event_raw_sched_switch *ctx)
{
	__u64 ts = bpf_ktime_get_ns();
	__u32 key = 0;
	struct stats *s;

	s = bpf_map_lookup_elem(&tp_stats, &key);
	if (!s)
		return 0;

	s->count++;

	if (read_fields) {
		/* 直接访问已解析的字段（无需 CO-RE） */
		__u32 prev_pid = ctx->prev_pid;
		__u32 next_pid = ctx->next_pid;

		/* 偶尔打印一次，避免刷屏 */
		if ((s->count & 0xFFF) == 0)
			bpf_printk("[tp]    switch: %d → %d", prev_pid, next_pid);
	}

	s->total_ns += bpf_ktime_get_ns() - ts;
	return 0;
}

/* ── 程序 2: RAW_TRACEPOINT（原始参数）──
 *
 * ctx 是原始的内核函数参数数组。
 * args[0] = prev (struct task_struct *)
 * args[1] = next (struct task_struct *)
 * 需要用 BPF_CORE_READ 从 task_struct 中读取 pid/comm。
 */
SEC("raw_tp/sched_switch")
int count_raw_tp(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 ts = bpf_ktime_get_ns();
	__u32 key = 0;
	struct stats *s;

	s = bpf_map_lookup_elem(&raw_tp_stats, &key);
	if (!s)
		return 0;

	s->count++;

	if (read_fields) {
		/* 从原始参数中读取 task_struct 指针 */
		struct task_struct *prev = (struct task_struct *)ctx->args[0];
		struct task_struct *next = (struct task_struct *)ctx->args[1];

		/* 需要用 BPF_CORE_READ 读取 pid（CO-RE 方式） */
		__u32 prev_pid = BPF_CORE_READ(prev, pid);
		__u32 next_pid = BPF_CORE_READ(next, pid);

		if ((s->count & 0xFFF) == 0)
			bpf_printk("[raw_tp] switch: %d → %d", prev_pid, next_pid);
	}

	s->total_ns += bpf_ktime_get_ns() - ts;
	return 0;
}
