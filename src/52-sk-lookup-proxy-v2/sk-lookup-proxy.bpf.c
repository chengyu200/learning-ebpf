// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 52-sk-lookup-proxy: 内核态 sk_lookup BPF 程序。
 *
 * 拦截发往端口 8000-8099 的入站 TCP 连接，通过 bpf_sk_assign()
 * 将连接重定向到 SOCKMAP 中的后端 listening socket（监听 9000）。
 *
 * 同时把原始目的端口存入 orig_port_map（key=socket cookie），
 * 用户态 accept 后可通过 SO_COOKIE 查找原始端口。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "sk-lookup-proxy.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* SOCKMAP：存储后端 listening socket 引用。 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} backend_socks SEC(".maps");

/*
 * 原始端口映射表：key = {客户端源IP, 源端口}, value = 原始目的端口
 *
 * sk_lookup 钩子触发时，ctx 包含入站包的完整五元组。
 * 我们用客户端的源 IP + 源端口作为 key（在 BPF 和用户态都能获取），
 * 把原始目的端口（ctx->local_port）存入 hash map。
 * 用户态 accept() 后用 getpeername() 获取客户端 IP:Port，查 map。
 */
struct conn_key {
	__u32 remote_ip4;   /* 客户端源 IP（网络字节序） */
	__u16 remote_port;  /* 客户端源端口（网络字节序） */
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct conn_key);
	__type(value, __u32);  /* 原始目的端口 */
} orig_port_map SEC(".maps");

/*
 * sk_lookup 主函数：每次传输层查找 socket 时触发。
 *
 * @ctx  bpf_sk_lookup 上下文，包含入站包的五元组信息
 *       ctx->local_port 是客户端连接的原始目的端口
 * @return SK_PASS = 放行，SK_DROP = 丢弃
 */
SEC("sk_lookup")
int l7_proxy(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	__u32 key = 0, orig_port;
	int err;

	/* 只处理 TCP */
	if (ctx->protocol != IPPROTO_TCP)
		return SK_PASS;

	/* 只拦截代理端口范围 8000-8099 */
	if (ctx->local_port < PROXY_PORT_START ||
	    ctx->local_port > PROXY_PORT_END)
		return SK_PASS;

	/* 从 SOCKMAP 查找后端 socket */
	sk = bpf_map_lookup_elem(&backend_socks, &key);
	if (!sk)
		return SK_PASS;

	/*
	 * 记录原始目的端口：
	 * 用客户端的源 IP + 源端口作为 key，
	 * 把 ctx->local_port（原始端口）存入 hash map。
	 * 用户态 accept() 后用 getpeername() 获取客户端 IP:Port，查 map。
	 */
	struct conn_key ck = {
		.remote_ip4 = ctx->remote_ip4,
		.remote_port = ctx->remote_port,
		.pad = 0,
	};
	orig_port = ctx->local_port;
	bpf_map_update_elem(&orig_port_map, &ck, &orig_port, BPF_ANY);

	/* 将后端 socket 分配给此入站连接 */
	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);

	return SK_PASS;
}
