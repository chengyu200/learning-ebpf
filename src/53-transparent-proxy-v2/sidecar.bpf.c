// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-transparent-proxy-v2: 内核态 BPF 程序（入流量 + 出流量劫持 + sk_msg 加速）。
 *
 * v1 能力：
 *   1. connect4 入流量：客户端 connect(127.0.0.1:8080) → 改写 dst port 为 15006
 *   2. sockops 桥接 cookie→conn_key + 填充 SOCKHASH
 *   3. sk_msg 本地流量加速
 *
 * v2 新增：
 *   4. connect4 出流量：server connect(任意远程) → 改写 dst 为 127.0.0.1:15006
 *      仅当 PID == server_pid_map[0] 时触发，其他进程出连接放行。
 *      保存原始目的到 orig_dst_map（含远程 IP+Port）。
 *
 * Map 生命周期同 v1：orig_dst_map[cookie] connect4 写入 → sockops 读取删除；
 * conn_map[{ip,port}] sockops 写入 → 用户态 accept 读取删除。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "proxy.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

/* sidecar PID — 防递归 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} sidecar_pid_map SEC(".maps");

/* v2: server PID — 出流量劫持仅对 server 生效 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} server_pid_map SEC(".maps");

/* 临时映射：cookie → 原始目的地址 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct orig_dst);
} orig_dst_map SEC(".maps");

/* 查询映射：客户端源 {ip,port} → 原始目的地址 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct orig_dst);
} conn_map SEC(".maps");

/* SOCKHASH：sk_msg redirect 用 */
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

/* cgroup/connect4：入流量 + 出流量劫持 */
SEC("cgroup/connect4")
int hijack_connect(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	__u32 *sidecar_pid, *server_pid;
	__u32 cur_pid;
	__u64 cookie;
	struct orig_dst orig = {};

	if (ctx->family != AF_INET)
		return 1;

	cur_pid = (bpf_get_current_pid_tgid() >> 32);

	/* 防递归：sidecar 自身 connect 放行 */
	sidecar_pid = bpf_map_lookup_elem(&sidecar_pid_map, &zero);
	if (sidecar_pid && *sidecar_pid == cur_pid)
		return 1;

	/* ── 入流量分支：dst == 127.0.0.1:8080 ── */
	if (ctx->user_ip4 == LOCALHOST_IPV4 &&
	    ctx->user_port == bpf_htons(SERVER_PORT)) {
		cookie = bpf_get_socket_cookie(ctx);
		orig.ip4 = ctx->user_ip4;
		orig.port = ctx->user_port;
		orig.pad = 0;
		bpf_map_update_elem(&orig_dst_map, &cookie, &orig, BPF_ANY);
		ctx->user_port = bpf_htons(SIDECAR_PORT);
		bpf_printk("hijack(in): cookie=%llu pid=%d :8080->:%d",
			   cookie, cur_pid, SIDECAR_PORT);
		return 1;
	}

	/* ── 出流量分支：仅 server PID 的非本地出连接 ── */
	server_pid = bpf_map_lookup_elem(&server_pid_map, &zero);
	if (!server_pid || *server_pid != cur_pid)
		return 1;

	/* 跳过已指向 sidecar 的连接（避免重复改写） */
	if (ctx->user_ip4 == LOCALHOST_IPV4 &&
	    ctx->user_port == bpf_htons(SIDECAR_PORT))
		return 1;

	/* 跳过 server bind/listen 的本地端口（不应被劫持） */
	if (ctx->user_ip4 == LOCALHOST_IPV4)
		return 1;

	/* 保存原始目的（含远程 IP+Port），改写到 sidecar */
	cookie = bpf_get_socket_cookie(ctx);
	orig.ip4 = ctx->user_ip4;
	orig.port = ctx->user_port;
	orig.pad = 0;
	bpf_map_update_elem(&orig_dst_map, &cookie, &orig, BPF_ANY);

	bpf_printk("hijack(out): cookie=%llu pid=%d %pI4:%d->127.0.0.1:%d",
		   cookie, cur_pid, &ctx->user_ip4,
		   bpf_ntohs(ctx->user_port), SIDECAR_PORT);

	ctx->user_ip4 = LOCALHOST_IPV4;
	ctx->user_port = bpf_htons(SIDECAR_PORT);
	return 1;
}

/* sockops：桥接 cookie → conn_key + 填充 SOCKHASH */
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

	/* SOCKHASH 仅对本地连接填充（sk_msg 加速仅对本地有意义） */
	if (skops->local_ip4 == LOCALHOST_IPV4 &&
	    skops->remote_ip4 == LOCALHOST_IPV4) {
		skey.sip = skops->local_ip4;
		skey.dip = skops->remote_ip4;
		skey.sport = bpf_htonl(skops->local_port);
		skey.dport = skops->remote_port;
		skey.family = skops->family;
		bpf_sock_hash_update(skops, &sock_ops_map, &skey, BPF_NOEXIST);
	}

	/* 仅 ACTIVE 侧做 cookie→conn_key 桥接 */
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

	bpf_printk("sockops: bridge cookie=%llu port=%d->orig %pI4:%d",
		   cookie, bpf_ntohs(ck.port), &orig->ip4, bpf_ntohs(orig->port));
	return BPF_OK;
}

/* sk_msg：本地 sendmsg 时 redirect 绕过协议栈 */
SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
	struct sock_key key = {};

	if (msg->remote_ip4 != LOCALHOST_IPV4 ||
	    msg->local_ip4 != LOCALHOST_IPV4)
		return SK_PASS;

	key.sip = msg->remote_ip4;
	key.dip = msg->local_ip4;
	key.dport = bpf_htonl(msg->local_port);
	key.sport = msg->remote_port;
	key.family = msg->family;

	bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
	return SK_PASS;
}
