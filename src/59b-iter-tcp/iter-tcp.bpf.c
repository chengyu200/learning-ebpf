// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 59b-iter-tcp: BPF 内核态 — iter/tcp 遍历 TCP 连接。
 *
 * 注意：SEC 名是 "iter/tcp"（不是 "iter/tcp4"）。
 * vmlinux.h 中的上下文结构体是 bpf_iter__tcp。
 *
 * 用 bpf_seq_write 二进制输出每个 TCP 连接的四元组 + 状态。
 * 用户态 read() 获取二进制流后解析打印，类似 ss -t。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "iter-tcp.h"

char LICENSE[] SEC("license") = "GPL";

SEC("iter/tcp")
int dump_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	struct tcp_event e = {};

	if (skc == NULL)
		return 0;

	e.saddr = BPF_CORE_READ(skc, skc_rcv_saddr);
	e.daddr = BPF_CORE_READ(skc, skc_daddr);
	e.sport = BPF_CORE_READ(skc, skc_num);
	e.dport = bpf_ntohs(BPF_CORE_READ(skc, skc_dport));
	e.state = BPF_CORE_READ(skc, skc_state);

	bpf_seq_write(ctx->meta->seq, &e, sizeof(e));
	return 0;
}
