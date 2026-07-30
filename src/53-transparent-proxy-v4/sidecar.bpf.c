// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-transparent-proxy-v4: 内核态 BPF 程序。
 *
 * v4 关键变化：端口一致（server 监听 :8080，与用户访问端口相同）。
 *   防回环机制从「端口区分」改为「PID 排除」：
 *   sk_lookup 中检查 bpf_get_current_pid_tgid()，若为 sidecar PID 则跳过。
 *
 * 实验性质：sk_lookup 可能运行在 softirq 上下文，PID 检测不一定可靠。
 *   - 成功：sidecar 回源 connect(127.0.0.1:8080) 时 sk_lookup 返回 SK_PASS
 *   - 失败：PID 不匹配，sidecar 回源被再次拦截 → 死循环 → 需备选方案
 *
 * 双钩子架构：
 *   1. sk_lookup（netns 级）：入流量劫持 + PID 排除防回环
 *   2. cgroup/connect4（cgroup 级）：出流量劫持（仅 server PID）
 *   3. sockops：桥接 cookie→conn_key + 填充 SOCKHASH
 *   4. sk_msg：本地流量加速
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "proxy.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

/* ─── Maps ─── */

/* sidecar 的 listening socket fd，供 sk_lookup 用 bpf_sk_assign */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sidecar_socks SEC(".maps");

/* sidecar PID — 防递归 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} sidecar_pid_map SEC(".maps");

/* server PID — 出流量劫持仅对 server 生效 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} server_pid_map SEC(".maps");

/* 临时映射：cookie → 原始目的地址（仅出流量写入） */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct orig_dst);
} orig_dst_map SEC(".maps");

/* 查询映射：发起方源 {ip,port} → 原始目的地址（仅出流量，供 sidecar 查 getpeername） */
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

/* sk_msg redirect 统计：[0]=hit, [1]=miss */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} redir_stats SEC(".maps");

/* ─── 1. sk_lookup：入流量劫持（netns 级）+ PID 排除防回环 ─── */
SEC("sk_lookup")
int inbound_lookup(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	__u32 key = 0;
	__u32 *sidecar_pid;
	__u32 cur_pid;

	if (ctx->protocol != IPPROTO_TCP)
		return SK_PASS;

	/* 仅拦截 :8080 */
	if (ctx->local_port != VIRTUAL_PORT)
		return SK_PASS;

	/* ── v4 防回环：PID 排除 ──
	 * sidecar 回源 connect(127.0.0.1:8080) 时，sk_lookup 会再次触发。
	 * 若当前 PID == sidecar PID，则跳过，让连接到达 server。
	 *
	 * 风险：sk_lookup 可能运行在 softirq 上下文，PID 不一定是 sidecar。
	 * trace_pipe 中观察 SKIP 日志是否出现即可判定。 */
	sidecar_pid = bpf_map_lookup_elem(&sidecar_pid_map, &key);
	if (sidecar_pid) {
		cur_pid = bpf_get_current_pid_tgid() >> 32;
		if (cur_pid == *sidecar_pid) {
			bpf_printk("sk_lookup: SKIP sidecar pid=%d", cur_pid);
			return SK_PASS;
		}
		bpf_printk("sk_lookup: INTERCEPT pid=%d sidecar=%d",
			   cur_pid, *sidecar_pid);
	}

	/* 外部 client → 重定向到 sidecar */
	sk = bpf_map_lookup_elem(&sidecar_socks, &key);
	if (!sk)
		return SK_PASS;
	bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	return SK_PASS;
}

/* ─── 2. cgroup/connect4：出流量劫持（仅 server PID） ─── */
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

	/* 仅劫持 server PID 的出连接 */
	server_pid = bpf_map_lookup_elem(&server_pid_map, &zero);
	if (!server_pid || *server_pid != cur_pid)
		return 1;

	/* 跳过已指向 sidecar 的连接 */
	if (ctx->user_ip4 == LOCALHOST_IPV4 &&
	    ctx->user_port == bpf_htons(SIDECAR_PORT))
		return 1;

	/* 跳过本地连接（server 回连本地不应劫持） */
	if (ctx->user_ip4 == LOCALHOST_IPV4)
		return 1;

	/* 保存原始目的，改写到 sidecar */
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

/* ─── 3. sockops：桥接 cookie→conn_key + 填充 SOCKHASH ─── */
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
		int hash_ret = bpf_sock_hash_update(skops, &sock_ops_map,
						    &skey, BPF_NOEXIST);
		bpf_printk("sockops: op=%d lp=%u rp=%u hash_ret=%d",
			   skops->op, skops->local_port,
			   bpf_ntohl(skops->remote_port), hash_ret);
	}

	/* 仅 ACTIVE 侧做 cookie→conn_key 桥接（出流量用） */
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

/* ─── 4. sk_msg：本地流量加速 ─── */
SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
	struct sock_key key = {};
	__u32 stat_key;
	__u64 *cnt;
	int ret;

	if (msg->remote_ip4 != LOCALHOST_IPV4 ||
	    msg->local_ip4 != LOCALHOST_IPV4)
		return SK_PASS;

	key.sip = msg->remote_ip4;
	key.dip = msg->local_ip4;
	key.dport = bpf_htonl(msg->local_port);
	key.sport = msg->remote_port;
	key.family = msg->family;

	ret = bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);

	stat_key = (ret == SK_PASS) ? 0 : 1;  /* 0=hit, 1=miss; SK_PASS=1 on success */
	cnt = bpf_map_lookup_elem(&redir_stats, &stat_key);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);

	if (ret == SK_PASS)
		bpf_printk("sk_msg: REDIRECT hit %u->%u",
			   msg->local_port,
			   bpf_ntohl(msg->remote_port));
	else
		bpf_printk("sk_msg: MISS ret=%d lp=%u rp=%u",
			   ret, msg->local_port,
			   bpf_ntohl(msg->remote_port));

	return SK_PASS;
}
