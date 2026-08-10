// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 80-cgroup-sockopt: 内核态 BPF 程序 — Socket 选项防火墙 + 审计器。
 *
 * 两个 BPF 程序覆盖 BPF_PROG_TYPE_CGROUP_SOCKOPT 的两个挂载点：
 *
 *   1. SEC("cgroup/setsockopt") — 安全策略 + 审计
 *      - 禁止修改 SO_REUSEADDR（防止端口劫持）
 *      - 其他选项放行，发送审计事件
 *
 *   2. SEC("cgroup/getsockopt") — 审计 + 透明改写
 *      - 记录所有 getsockopt 调用
 *      - 演示改写：读取 IP_TTL 时强制返回 64
 *
 * 上下文：struct bpf_sockopt {
 *   struct bpf_sock *sk;       // 关联的 socket
 *   void *optval;              // 选项值缓冲区
 *   void *optval_end;          // 缓冲区末尾
 *   __s32 level;               // SOL_SOCKET / SOL_IP
 *   __s32 optname;             // SO_REUSEADDR / IP_TTL
 *   __s32 optlen;              // 选项值长度
 *   __s32 retval;              // 返回值（getsockopt 可设置）
 * }
 *
 * 返回值语义（来自内核源码 kernel/bpf/cgroup.c 的 bpf_prog_run_array_cg）：
 *   return 1 = ALLOW（retval 不变，保持初始值 0 = 成功）
 *   return 0 = DENY（retval 被强制设为 -EPERM）
 *
 * 要拒绝并返回特定 errno：
 *   bpf_set_retval(-EPERM);  // 设置 retval
 *   return 1;                // 1=ALLOW signal，但 retval 已是 -EPERM
 *
 * setsockopt 和 getsockopt 在 bpf_prog_run_array_cg 层面返回值语义相同，
 * 但调用后的处理不同（见下方各程序的注释）。
 *
 * 教学概念：
 * - SEC("cgroup/getsockopt") / SEC("cgroup/setsockopt")
 * - bpf_sockopt 上下文：level/optname/optlen/optval/optval_end
 * - 返回值：1=ALLOW, 0=DENY（EPERM）
 * - getsockopt 改写：修改 optval + 设置 optlen
 * - optval/optval_end 边界检查（类似 TC 的 data/data_end）
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "cgroup-sockopt.h"

char LICENSE[] SEC("license") = "GPL";

/* ringbuf：事件通道 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ── 程序 1: cgroup/setsockopt — 安全策略 + 审计 ──
 *
 * 策略：禁止修改 SO_REUSEADDR
 *
 * 返回值语义（bpf_prog_run_array_cg 公共逻辑）：
 *   return 1 = ALLOW（retval 保持初始值 0 = 成功）
 *   return 0 = DENY（retval 被强制设为 -EPERM）
 *
 * 调用后处理（__cgroup_bpf_run_filter_setsockopt）：
 *   ret == 0（BPF return 1，retval=0）→ 继续处理：
 *     ctx.optlen == -1  → ret=1，跳过内核 setsockopt（BPF 完全处理）
 *     ctx.optlen >= 0   → ret=0，让内核正常处理 setsockopt
 *   ret < 0（BPF return 0，retval=-EPERM）→ 返回错误，setsockopt 失败
 *
 * 要拒绝：bpf_set_retval(-EPERM) + return 1（retval 已设为 -EPERM）
 * 要放行：return 1（retval 保持 0，内核继续处理）
 *
 * 内核源码关键逻辑（bpf_prog_run_array_cg）：
 *   func_ret = run_prog(prog, ctx);  // BPF 程序返回值
 *   func_ret &= 1;                   // 只取 bit 0
 *   if (!func_ret && !IS_ERR_VALUE(run_ctx.retval))
 *       run_ctx.retval = -EPERM;     // return 0 → 强制 -EPERM
 */
SEC("cgroup/setsockopt")
int cg_setsockopt(struct bpf_sockopt *ctx)
{
	struct event *e;
	__s32 level = ctx->level;
	__s32 optname = ctx->optname;
	int blocked = 0;

	/* 安全策略：禁止修改 SO_REUSEADDR */
	if (level == SOL_SOCKET && optname == SO_REUSEADDR)
		blocked = 1;

	/* 发送审计事件 */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->op       = OP_SETSOCKOPT;
		e->decision = blocked ? DEC_BLOCKED : DEC_ALLOWED;
		e->level    = level;
		e->optname  = optname;
		e->optlen   = ctx->optlen;
		e->pid      = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}

	if (blocked) {
		bpf_set_retval(-EPERM);
		return 1;  /* retval=-EPERM → setsockopt 返回 EPERM */
	}
	return 1;  /* retval=0 → 成功，内核继续处理 setsockopt */
}

/* ── 程序 2: cgroup/getsockopt — 审计 + 透明改写 ──
 *
 * 策略：读取 IP_TTL 时强制返回 64
 *
 * 返回值语义（bpf_prog_run_array_cg 公共逻辑，与 setsockopt 相同）：
 *   return 1 = ALLOW（retval 不变）
 *   return 0 = DENY（retval 被强制设为 -EPERM）
 *
 * 调用后处理（__cgroup_bpf_run_filter_getsockopt）：
 *   BPF 程序在内核 getsockopt **之后**运行：
 *     1. 内核先执行 getsockopt，将结果写入 optval/optlen
 *     2. 内核返回值作为 retval 传给 bpf_prog_run_array_cg
 *     3. BPF 程序可以读取和改写 optval/optlen
 *     4. return 1 后，如果 ctx.optlen != 0，BPF 的 optval/optlen 复制给用户
 *
 * 与 setsockopt 的关键区别：
 *   - getsockopt 没有 optlen=-1 跳过内核的机制
 *   - BPF 是在内核 getsockopt 之后运行，可以读取和改写内核返回的值
 *   - setsockopt 的 BPF 在内核 setsockopt 之前运行，可以选择跳过内核
 *
 * 改写 IP_TTL 时：写 optval + 设 optlen + return 1
 * 非改写的选项：直接 return 1（允许，不设 retval = 成功）
 */
SEC("cgroup/getsockopt")
int cg_getsockopt(struct bpf_sockopt *ctx)
{
	struct event *e;
	__s32 level = ctx->level;
	__s32 optname = ctx->optname;
	int rewritten = 0;
	int val = 0;

	/* 透明改写：IP_TTL → 64 */
	if (level == SOL_IP && optname == IP_TTL) {
		/* 边界检查：确保 optval 有足够空间写 4 字节 */
		__u32 *optval = ctx->optval;
		__u32 *optval_end = ctx->optval_end;

		if ((void *)(optval + 1) <= (void *)optval_end) {
			*optval = 64;		/* 改写 TTL 值 */
			ctx->optlen = 4;	/* 设置返回长度 */
			rewritten = 1;
			val = 64;
		}
	}

	/* 发送审计事件 */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->op             = OP_GETSOCKOPT;
		e->decision       = rewritten ? DEC_REWRITTEN : DEC_ALLOWED;
		e->level          = level;
		e->optname        = optname;
		e->optlen         = ctx->optlen;
		e->rewritten_val  = val;
		e->pid            = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}

	/* return 1 = ALLOW（retval 保持初始值 0 = 成功）
	 * 改写后的 optval/optlen 会被复制给用户 */
	return 1;
}
