// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 52-sk-lookup-proxy: 内核态 sk_lookup BPF 程序。
 *
 * 拦截发往端口 8000-8099 的入站 TCP 连接，通过 bpf_sk_assign()
 * 将连接重定向到 SOCKMAP 中的后端 listening socket（监听 9000）。
 *
 * 工作流程：
 *   1. 客户端 connect(127.0.0.1:8000)
 *   2. 内核传输层查找 socket → 触发 sk_lookup 钩子
 *   3. BPF 程序检查：是 TCP? 端口在 8000-8099?
 *   4. 从 SOCKMAP 查找后端 socket
 *   5. bpf_sk_assign() 分配后端 socket 接收此连接
 *   6. 后端 HTTP 服务器 accept() 并响应
 *
 * 教学概念：
 * - BPF_PROG_TYPE_SK_LOOKUP：在传输层 socket 查找阶段介入
 * - bpf_sk_assign：选择哪个 socket 接收入站连接
 * - BPF_MAP_TYPE_SOCKMAP：存储 socket 引用
 * - 挂载到网络命名空间（不是 cgroup 或网卡）
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "sk-lookup-proxy.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* SOCKMAP：存储后端 listening socket 引用。
 * key=0 对应后端服务器 socket。
 * 用户态在启动时用 bpf_map_update_elem 写入。 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} backend_socks SEC(".maps");

/*
 * sk_lookup 主函数：每次传输层查找 socket 时触发。
 *
 * 只对"未建立连接"的包触发（TCP LISTEN / UDP 未连接），
 * 已建立连接的包不走此钩子。
 *
 * @ctx  bpf_sk_lookup 上下文，包含入站包的五元组信息
 * @return SK_PASS = 放行（可能有 socket assign），SK_DROP = 丢弃
 */
SEC("sk_lookup")
int l7_proxy(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	__u32 key = 0;
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
		return SK_PASS;  /* 没有后端 → 继续传统查找 */

	/* 将后端 socket 分配给此入站连接 */
	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);  /* 释放 lookup 获取的引用 */

	if (err)
		return SK_PASS;  /* assign 失败 → 回退到传统查找 */

	return SK_PASS;  /* assign 成功，内核会使用我们选择的 socket */
}
