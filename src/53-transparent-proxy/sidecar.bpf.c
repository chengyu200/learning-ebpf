// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-transparent-proxy: 内核态 BPF 程序。
 *
 * M1: connect4 劫持 + sockops 桥接 orig_dst。
 * M2: + sk_msg/SOCKHASH 本地流量加速（绕过 TCP/IP 协议栈）。
 *
 * 数据流：
 *   1. connect4：客户端 connect(127.0.0.1:8080) → 改写 dst port 为 15006，
 *      同时以 socket cookie 为 key 保存原始目的地址到 orig_dst_map。
 *   2. sockops：连接建立后（ACTIVE/PASSIVE_ESTABLISHED_CB），将 cookie→orig_dst
 *      桥接为 conn_key→orig_dst，供 sidecar 用户态 accept 后查 getpeername 反查。
 *      同时填充 SOCKHASH，使 sk_msg 可在本地连接间直接 redirect。
 *   3. sk_msg：本地 sendmsg 时查 SOCKHASH，命中则 bpf_msg_redirect_hash 绕过协议栈。
 *
 * 三个 map 的生命周期：
 *   orig_dst_map[cookie]：connect4 写入，sockops ACTIVE 读取后删除
 *   conn_map[{ip,port}]：sockops ACTIVE 写入，用户态 accept 后读取并删除
 *   sock_ops_map[sock_key]：sockops 两侧写入，sk_msg 查询用于 redirect
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "proxy.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

/* sidecar PID — 防递归（sidecar 自身 connect 时跳过改写） */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} sidecar_pid_map SEC(".maps");

/* 临时映射：cookie → 原始目的地址 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);            /* socket cookie */
	__type(value, struct orig_dst);
} orig_dst_map SEC(".maps");

/* 查询映射：客户端源 {ip,port} → 原始目的地址 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct orig_dst);
} conn_map SEC(".maps");

/* SOCKHASH：sk_msg redirect 用（复用 29-sockops 的 sock_key 模式） */
struct sock_key {
	__u32 sip;
	__u32 dip;
	__u32 sport;
	__u32 dport;
	__u32 family;
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65535);
	__type(key, struct sock_key);
	__type(value, int);
} sock_ops_map SEC(".maps");

/* cgroup/connect4：拦截 connect()，改写目的地址 */
SEC("cgroup/connect4")
int hijack_connect(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	__u32 *sidecar_pid;
	__u64 cookie;
	struct orig_dst orig = {};

	if (ctx->family != AF_INET)
		return 1;

	/* 防递归：sidecar 自身的 connect() 直接放行 */
	sidecar_pid = bpf_map_lookup_elem(&sidecar_pid_map, &zero);
	if (sidecar_pid && *sidecar_pid == (bpf_get_current_pid_tgid() >> 32))
		return 1;

	/* 仅劫持目标为 127.0.0.1:8080 的连接 */
	if (ctx->user_ip4 != LOCALHOST_IPV4)
		return 1;
	if (ctx->user_port != bpf_htons(SERVER_PORT))
		return 1;

	/* 保存原始目的地址，key = socket cookie */
	cookie = bpf_get_socket_cookie(ctx);
	orig.ip4 = ctx->user_ip4;
	orig.port = ctx->user_port;
	orig.pad = 0;
	bpf_map_update_elem(&orig_dst_map, &cookie, &orig, BPF_ANY);

	/* 改写目的端口为 sidecar */
	ctx->user_port = bpf_htons(SIDECAR_PORT);

	bpf_printk("hijack: cookie=%llu pid=%d %d->%d",
		   cookie, (int)(bpf_get_current_pid_tgid() >> 32),
		   SERVER_PORT, SIDECAR_PORT);
	return 1;
}

/* sockops：连接建立后桥接 cookie → 客户端源 4-tuple + 填充 SOCKHASH */
SEC("sockops")
int bpf_sockops_handler(struct bpf_sock_ops *skops)
{
	struct sock_key skey = {};
	struct conn_key ck = {};
	struct orig_dst *orig;
	__u64 cookie;

	if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
	    skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
		return BPF_OK;

	/* 仅处理本地回环连接（sk_msg 加速仅对本地连接有意义） */
	if (skops->local_ip4 != LOCALHOST_IPV4 ||
	    skops->remote_ip4 != LOCALHOST_IPV4)
		return BPF_OK;

	/* 填充 SOCKHASH（连接两侧都填，使 sk_msg 双向 redirect 生效） */
	skey.sip = skops->local_ip4;
	skey.dip = skops->remote_ip4;
	skey.sport = bpf_htonl(skops->local_port);
	skey.dport = skops->remote_port;
	skey.family = skops->family;
	bpf_sock_hash_update(skops, &sock_ops_map, &skey, BPF_NOEXIST);

	/* 仅 ACTIVE 侧做 cookie→conn_key 桥接（PASSIVE 侧无 orig_dst_map 条目） */
	if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
		return BPF_OK;

	cookie = bpf_get_socket_cookie(skops);
	orig = bpf_map_lookup_elem(&orig_dst_map, &cookie);
	if (!orig)
		return BPF_OK;

	ck.ip = skops->local_ip4;
	ck.port = bpf_htons(skops->local_port);
	ck.pad = 0;

	bpf_map_update_elem(&conn_map, &ck, orig, BPF_ANY);
	bpf_map_delete_elem(&orig_dst_map, &cookie);

	bpf_printk("sockops: bridge cookie=%llu port=%d->%d",
		   cookie, bpf_ntohs(ck.port), bpf_ntohs(orig->port));
	return BPF_OK;
}

/* sk_msg：本地 sendmsg 时查 SOCKHASH，命中则 redirect 绕过 TCP/IP 协议栈 */
SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
	struct sock_key key = {};

	if (msg->remote_ip4 != LOCALHOST_IPV4 ||
	    msg->local_ip4 != LOCALHOST_IPV4)
		return SK_PASS;

	/* key 取接收端视角，匹配 PASSIVE_ESTABLISHED 写入的条目 */
	key.sip = msg->remote_ip4;
	key.dip = msg->local_ip4;
	key.dport = bpf_htonl(msg->local_port);
	key.sport = msg->remote_port;
	key.family = msg->family;

	bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
	return SK_PASS;
}
