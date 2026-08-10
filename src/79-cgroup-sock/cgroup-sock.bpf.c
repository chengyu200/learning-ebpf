// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 79-cgroup-sock: Socket lifecycle auditor - BPF programs.
 *
 * Program type: BPF_PROG_TYPE_CGROUP_SOCK
 * Context:     struct bpf_sock (UAPI, not in vmlinux.h/BTF)
 *
 * Four programs covering 5 SEC names:
 *   ① SEC("cgroup/sock_create")  — socket creation (deny raw socket)
 *   ② SEC("cgroup/post_bind4")   — IPv4 bind address logging
 *   ③ SEC("cgroup/post_bind6")   — IPv6 bind address logging
 *   ④ SEC("cgroup/sock_release") — socket release logging
 *
 * Note: SEC("cgroup/sock") is a legacy alias for SEC("cgroup/sock_create")
 *   (same attach type BPF_CGROUP_INET_SOCK_CREATE, but SEC_ATTACHABLE_OPT
 *   instead of SEC_ATTACHABLE — expected_attach_type is optional).
 *
 * Return values: 1 = allow, 0 = deny (same convention as cgroup/dev).
 *   sock_release return value is ignored by the kernel.
 *
 * struct bpf_sock fields (UAPI bpf.h):
 *   __u32 bound_dev_if, family, type, protocol, mark, priority;
 *   __u32 src_ip4, src_ip6[4], src_port;   (src_port = host byte order)
 *   __be16 dst_port;                       (dst_port = network byte order)
 *   __u32 dst_ip4, dst_ip6[4], state;
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "cgroup-sock.h"

char LICENSE[] SEC("license") = "GPL";

/* Ringbuf: event channel to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct event *new_event(__u8 ev_type)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return NULL;
	e->type = ev_type;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->ts_ns = bpf_ktime_get_ns();
	return e;
}

/* ① cgroup/sock_create — log socket creation, deny raw sockets.
 *
 * Note: SEC("cgroup/sock") is a legacy alias for this (same attach type).
 */
SEC("cgroup/sock_create")
int sock_create(struct bpf_sock *ctx)
{
	__u8 allowed = 1;

	/* Policy: deny raw sockets (protocol == IPPROTO_RAW = 255) */
	if (ctx->protocol == IPPROTO_RAW_VAL)
		allowed = 0;

	struct event *e = new_event(EV_SOCK_CREATE);
	if (e) {
		e->allowed   = allowed;
		e->family     = ctx->family;
		e->sock_type  = ctx->type;
		e->protocol   = ctx->protocol;
		bpf_ringbuf_submit(e, 0);
	}

	return allowed;
}

/* ② cgroup/post_bind4 — log IPv4 bind (src_ip4 + src_port) */
SEC("cgroup/post_bind4")
int post_bind4(struct bpf_sock *ctx)
{
	struct event *e = new_event(EV_BIND4);
	if (e) {
		e->family    = ctx->family;
		e->sock_type = ctx->type;
		e->protocol  = ctx->protocol;
		e->src_ip4   = ctx->src_ip4;
		e->src_port  = (__u16)ctx->src_port;
		bpf_ringbuf_submit(e, 0);
	}

	return 1;
}

/* ③ cgroup/post_bind6 — log IPv6 bind (src_ip6 + src_port) */
SEC("cgroup/post_bind6")
int post_bind6(struct bpf_sock *ctx)
{
	struct event *e = new_event(EV_BIND6);
	if (e) {
		e->family    = ctx->family;
		e->sock_type = ctx->type;
		e->protocol  = ctx->protocol;
		e->src_ip6[0] = ctx->src_ip6[0];
		e->src_ip6[1] = ctx->src_ip6[1];
		e->src_ip6[2] = ctx->src_ip6[2];
		e->src_ip6[3] = ctx->src_ip6[3];
		e->src_port  = (__u16)ctx->src_port;
		bpf_ringbuf_submit(e, 0);
	}

	return 1;
}

/* ④ cgroup/sock_release — log socket release (return value ignored) */
SEC("cgroup/sock_release")
int sock_release(struct bpf_sock *ctx)
{
	struct event *e = new_event(EV_SOCK_RELEASE);
	if (e) {
		e->family    = ctx->family;
		e->sock_type = ctx->type;
		e->protocol  = ctx->protocol;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}
