// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 81-sk-reuseport: 内核态 BPF 程序 — SO_REUSEPORT 自定义连接分配。
 *
 * 两个 BPF 程序覆盖 BPF_PROG_TYPE_SK_REUSEPORT 的两个挂载点：
 *
 *   1. SEC("sk_reuseport") — BPF_SK_REUSEPORT_SELECT
 *      仅在新连接到来时触发（migrating_sk == NULL）
 *
 *   2. SEC("sk_reuseport/migrate") — BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
 *      新连接 + socket 关闭时连接迁移都触发
 *
 * 返回值语义（来自内核源码 net/core/filter.c 的 bpf_run_sk_reuseport）：
 *   SK_PASS (1) = 放行，使用 selected_sk（由 bpf_sk_select_reuseport 设置）
 *                 如果 selected_sk == NULL，内核回退到默认 hash 选择
 *   SK_DROP  (0) = 拒绝连接（ECONNREFUSED）
 *
 * 选择 socket 的方式：
 *   调用 bpf_sk_select_reuseport(ctx, map, key, flags) 从 REUSEPORT_SOCKARRAY
 *   map 中选择一个 socket，设置 ctx->selected_sk。
 *
 * 如果不需要自定义选择，返回 SK_PASS 即可让内核用默认 hash 分配。
 *
 * 上下文：struct sk_reuseport_md {
 *   void *data;              // TCP/UDP 头起始
 *   void *data_end;          // 可访问数据末尾
 *   __u32 len;               // 包总长度
 *   __u32 eth_protocol;      // ETH_P_IP / ETH_P_IPV6
 *   __u32 ip_protocol;       // IPPROTO_TCP / IPPROTO_UDP
 *   __u32 bind_inany;        // 绑定到 INANY 地址？
 *   __u32 hash;              // 包 4-tuple 的 hash
 *   struct bpf_sock *sk;     // 当前 socket（reuseport 组中的一个）
 *   struct bpf_sock *migrating_sk;  // 迁移中的 socket（NULL=选择，非NULL=迁移）
 * }
 *
 * attach 方式（非 bpf_link）：
 *   setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd))
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "sk-reuseport.h"

char LICENSE[] SEC("license") = "GPL";

#define SK_PASS 1
#define SK_DROP  0

/* REUSEPORT_SOCKARRAY map：存储 socket fd，供 bpf_sk_select_reuseport 使用 */
struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, NUM_SOCKETS);
	__type(key, __u32);
	__type(value, __u32);
} reuseport_array SEC(".maps");

/* ringbuf：事件通道 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* 共享日志函数 */
static __always_inline void log_event(struct sk_reuseport_md *ctx, __u8 op, __u8 selected)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;

	e->op          = op;
	e->selected    = selected;
	e->hash        = ctx->hash;
	e->ip_protocol = ctx->ip_protocol;
	e->pid         = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
}

/* ── 程序 1: sk_reuseport — 仅选择 ──
 *
 * 在新连接到来时触发（migrating_sk == NULL）
 *
 * 用 bpf_sk_select_reuseport 从 REUSEPORT_SOCKARRAY map 选择 socket：
 *   key = hash % NUM_SOCKETS → map[key] → selected_sk
 * 然后返回 SK_PASS 放行。
 */
SEC("sk_reuseport")
int select_prog(struct sk_reuseport_md *ctx)
{
	__u32 key = ctx->hash % NUM_SOCKETS;
	int ret;

	ret = bpf_sk_select_reuseport(ctx, &reuseport_array, &key, 0);
	log_event(ctx, OP_SELECT, (__u8)key);

	/* 即使 bpf_sk_select_reuseport 失败，也返回 SK_PASS
	 * 让内核回退到默认 hash 选择 */
	return SK_PASS;
}

/* ── 程序 2: sk_reuseport/migrate — 选择 + 迁移 ──
 *
 * 新连接（migrating_sk == NULL）→ 选择模式
 * 连接迁移（migrating_sk != NULL）→ 迁移模式
 *
 * 两种模式都用 bpf_sk_select_reuseport 选择 socket，返回 SK_PASS。
 */
SEC("sk_reuseport/migrate")
int migrate_prog(struct sk_reuseport_md *ctx)
{
	__u32 key = ctx->hash % NUM_SOCKETS;
	__u8 op;

	if (ctx->migrating_sk)
		op = OP_MIGRATE;
	else
		op = OP_SELECT;

	bpf_sk_select_reuseport(ctx, &reuseport_array, &key, 0);
	log_event(ctx, op, (__u8)key);

	return SK_PASS;
}
