// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 77-sock-addr-monitor: 内核态 BPF 程序 — Socket 地址操作审计器。
 *
 * 17 个 BPF 程序覆盖 BPF_PROG_TYPE_CGROUP_SOCK_ADDR 的所有挂载点：
 *
 *   bind4/6:              bind() 系统调用
 *   connect4/6/unix:      connect() 系统调用
 *   sendmsg4/6/unix:      UDP sendmsg()
 *   recvmsg4/6/unix:      UDP recvmsg()
 *   getpeername4/6/unix:  getpeername()
 *   getsockname4/6/unix:  getsockname()
 *
 * 上下文：struct bpf_sock_addr
 *
 * 重要：验证器按 hook 类型限制可访问的上下文字段：
 *   IPv4 hook（bind4 等）：只能读 user_ip4(offset 4)、user_port(24)，不能读 user_ip6(8-23)
 *   IPv6 hook（bind6 等）：只能读 user_ip6(offset 8-23)、user_port(24)，不能读 user_ip4(4)
 *   Unix hook：不能读 user_ip4/user_ip6/user_port
 *
 * 因此需要三个 log_event 变体：log_event4、log_event6、log_event_unix
 *
 * 返回值：1 = 允许操作（仅审计），0 = 拒绝
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sock-addr-monitor.h"

char LICENSE[] SEC("license") = "GPL";

/* ringbuf：事件通道 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* 共享日志函数：只访问所有 hook 都允许的字段
 * user_family(offset 0)、type(32)、protocol(36) 对所有 hook 类型可读 */
static __always_inline void log_common(struct bpf_sock_addr *ctx, __u8 op, struct event *e)
{
	e->op          = op;
	e->user_family = ctx->user_family;
	e->sock_type   = ctx->type;
	e->protocol    = ctx->protocol;
	e->pid         = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* IPv4 变体：可访问 user_ip4、user_port */
static __always_inline void log_event4(struct bpf_sock_addr *ctx, __u8 op)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;
	log_common(ctx, op, e);
	e->ip4  = ctx->user_ip4;
	e->port = bpf_ntohs(ctx->user_port);
	bpf_ringbuf_submit(e, 0);
}

/* IPv6 变体：可访问 user_ip6[4]、user_port */
static __always_inline void log_event6(struct bpf_sock_addr *ctx, __u8 op)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;
	log_common(ctx, op, e);
	e->ip6[0] = ctx->user_ip6[0];
	e->ip6[1] = ctx->user_ip6[1];
	e->ip6[2] = ctx->user_ip6[2];
	e->ip6[3] = ctx->user_ip6[3];
	e->port   = bpf_ntohs(ctx->user_port);
	bpf_ringbuf_submit(e, 0);
}

/* Unix 变体：不访问 IP/端口字段 */
static __always_inline void log_event_unix(struct bpf_sock_addr *ctx, __u8 op)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;
	log_common(ctx, op, e);
	bpf_ringbuf_submit(e, 0);
}

/* ── bind ── */
SEC("cgroup/bind4")
int bind4_hook(struct bpf_sock_addr *ctx) { log_event4(ctx, OP_BIND4); return 1; }

SEC("cgroup/bind6")
int bind6_hook(struct bpf_sock_addr *ctx) { log_event6(ctx, OP_BIND6); return 1; }

/* ── connect ── */
SEC("cgroup/connect4")
int connect4_hook(struct bpf_sock_addr *ctx) { log_event4(ctx, OP_CONNECT4); return 1; }

SEC("cgroup/connect6")
int connect6_hook(struct bpf_sock_addr *ctx) { log_event6(ctx, OP_CONNECT6); return 1; }

SEC("cgroup/connect_unix")
int connect_unix_hook(struct bpf_sock_addr *ctx) { log_event_unix(ctx, OP_CONNECT_UNIX); return 1; }

/* ── sendmsg (UDP) ── */
SEC("cgroup/sendmsg4")
int sendmsg4_hook(struct bpf_sock_addr *ctx) { log_event4(ctx, OP_SENDMSG4); return 1; }

SEC("cgroup/sendmsg6")
int sendmsg6_hook(struct bpf_sock_addr *ctx) { log_event6(ctx, OP_SENDMSG6); return 1; }

SEC("cgroup/sendmsg_unix")
int sendmsg_unix_hook(struct bpf_sock_addr *ctx) { log_event_unix(ctx, OP_SENDMSG_UNIX); return 1; }

/* ── recvmsg (UDP) ── */
SEC("cgroup/recvmsg4")
int recvmsg4_hook(struct bpf_sock_addr *ctx) { log_event4(ctx, OP_RECVMSG4); return 1; }

SEC("cgroup/recvmsg6")
int recvmsg6_hook(struct bpf_sock_addr *ctx) { log_event6(ctx, OP_RECVMSG6); return 1; }

SEC("cgroup/recvmsg_unix")
int recvmsg_unix_hook(struct bpf_sock_addr *ctx) { log_event_unix(ctx, OP_RECVMSG_UNIX); return 1; }

/* ── getpeername ── */
SEC("cgroup/getpeername4")
int getpeername4_hook(struct bpf_sock_addr *ctx) { log_event4(ctx, OP_GETPEERNAME4); return 1; }

SEC("cgroup/getpeername6")
int getpeername6_hook(struct bpf_sock_addr *ctx) { log_event6(ctx, OP_GETPEERNAME6); return 1; }

SEC("cgroup/getpeername_unix")
int getpeername_unix_hook(struct bpf_sock_addr *ctx) { log_event_unix(ctx, OP_GETPEERNAME_UNIX); return 1; }

/* ── getsockname ── */
SEC("cgroup/getsockname4")
int getsockname4_hook(struct bpf_sock_addr *ctx) { log_event4(ctx, OP_GETSOCKNAME4); return 1; }

SEC("cgroup/getsockname6")
int getsockname6_hook(struct bpf_sock_addr *ctx) { log_event6(ctx, OP_GETSOCKNAME6); return 1; }

SEC("cgroup/getsockname_unix")
int getsockname_unix_hook(struct bpf_sock_addr *ctx) { log_event_unix(ctx, OP_GETSOCKNAME_UNIX); return 1; }
