// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 66-struct-ops-tcp-cc: BPF 内核态 — 用 struct_ops 实现 TCP 拥塞控制。
 *
 * 实现 bpf_reno_trace：以 Reno 为基础（委托 ksym），叠加 CC 行为追踪。
 * 这是一个真正可用的 CC 算法——通过 setsockopt(TCP_CONGESTION) 选择。
 *
 * struct_ops 机制：
 *   SEC("struct_ops")  — 声明 BPF 程序作为 ops 回调
 *   SEC(".struct_ops") — 声明完整的 tcp_congestion_ops vtable
 *   libbpf 自动创建 BPF_MAP_TYPE_STRUCT_OPS map 并注册到内核
 *
 * 回调委托：
 *   cong_avoid → tcp_reno_cong_avoid（Reno 拥塞避免）+ 记录 cwnd
 *   ssthresh   → tcp_reno_ssthresh
 *   undo_cwnd  → tcp_reno_undo_cwnd
 *   init/release/set_state → 追踪日志
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcp_cc.h"

char LICENSE[] SEC("license") = "GPL";

/* 内核 ksym：Reno CC 函数，BPF 可以直接调用 */
extern void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked) __weak __ksym;
extern u32 tcp_reno_ssthresh(struct sock *sk) __weak __ksym;
extern u32 tcp_reno_undo_cwnd(struct sock *sk) __weak __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline void emit_event(__u8 type, struct sock *sk,
				       __u32 cwnd, __u32 ssthresh, __u8 state)
{
	struct cc_event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;
	e->type = type;
	e->state = state;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cwnd = cwnd;
	e->ssthresh = ssthresh;
	e->ts_ns = bpf_ktime_get_ns();
	bpf_ringbuf_submit(e, 0);
}

/* 连接初始化：CC 被选中时调用 */
SEC("struct_ops")
int BPF_PROG(cc_init, struct sock *sk)
{
	emit_event(EV_INIT, sk, 0, 0, 0);
	return 0;
}

/* 拥塞避免：委托 Reno + 记录 cwnd 变化 */
SEC("struct_ops")
int BPF_PROG(cc_cong_avoid, struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	u32 cwnd, ssthresh;

	tcp_reno_cong_avoid(sk, ack, acked);

	cwnd = BPF_CORE_READ(tp, snd_cwnd);
	ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
	emit_event(EV_CWND, sk, cwnd, ssthresh, 0);

	return 0;
}

/* 慢启动阈值：委托 Reno */
SEC("struct_ops")
int BPF_PROG(cc_ssthresh, struct sock *sk)
{
	return tcp_reno_ssthresh(sk);
}

/* 状态变迁：记录 CC 状态转换 */
SEC("struct_ops")
int BPF_PROG(cc_set_state, struct sock *sk, u8 new_state)
{
	emit_event(EV_STATE, sk, 0, 0, new_state);
	return 0;
}

/* 撤销 cwnd：委托 Reno */
SEC("struct_ops")
int BPF_PROG(cc_undo_cwnd, struct sock *sk)
{
	return tcp_reno_undo_cwnd(sk);
}

/* 连接释放 */
SEC("struct_ops")
int BPF_PROG(cc_release, struct sock *sk)
{
	emit_event(EV_RELEASE, sk, 0, 0, 0);
	return 0;
}

/* struct_ops vtable 声明 */
SEC(".struct_ops")
struct tcp_congestion_ops bpf_reno_trace = {
	.name        = CC_NAME,
	.init        = (void *)cc_init,
	.cong_avoid  = (void *)cc_cong_avoid,
	.ssthresh    = (void *)cc_ssthresh,
	.set_state   = (void *)cc_set_state,
	.undo_cwnd   = (void *)cc_undo_cwnd,
	.release     = (void *)cc_release,
};
