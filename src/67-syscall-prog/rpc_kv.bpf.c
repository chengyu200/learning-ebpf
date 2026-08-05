// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 67-syscall-prog: BPF 内核态 — syscall RPC 键值存储。
 *
 * BPF_PROG_TYPE_SYSCALL 程序，由用户态通过 BPF_PROG_RUN 主动触发。
 * 不挂载到任何内核 hook 点，上下文由用户态通过 ctx_in 提供。
 *
 * 功能：
 *   PUT key value   → bpf_map_update_elem
 *   LOOKUP key      → bpf_map_lookup_elem → 返回值
 *   DELETE key      → bpf_map_delete_elem
 *   STATS           → 返回 percpu 统计
 *
 * 独特能力（对比其他 BPF 程序类型）：
 *   - 用户态主动触发（BPF_PROG_RUN），非被动响应
 *   - 上下文由用户态提供（ctx_in）
 *   - 返回值直接传回用户态（retval）
 *   - 不需要 attach（加载即可用）
 *   - 默认 sleepable（可使用 bpf_copy_from_user 等）
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "rpc_kv.h"

char LICENSE[] SEC("license") = "GPL";

/* 键值存储 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, __u64);
} store SEC(".maps");

/* 操作统计（per-CPU） */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STATS_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

SEC("syscall")
int handle_rpc(struct rpc_req *req)
{
	__u32 key;
	__u64 val;
	__u32 skey;
	__u64 *cnt;

	if (!req)
		return -ERR_INVAL;

	switch (req->op) {
	case OP_PUT:
		key = req->key;
		val = req->value;
		bpf_map_update_elem(&store, &key, &val, BPF_ANY);
		skey = STATS_PUT;
		cnt = bpf_map_lookup_elem(&stats, &skey);
		if (cnt)
			*cnt += 1;
		return 0;

	case OP_LOOKUP:
		key = req->key;
		{
			__u64 *v = bpf_map_lookup_elem(&store, &key);
			skey = STATS_LOOKUP;
			cnt = bpf_map_lookup_elem(&stats, &skey);
			if (cnt)
				*cnt += 1;
			return v ? (int)*v : -ERR_NOENT;
		}

	case OP_DELETE:
		key = req->key;
		skey = STATS_DELETE;
		cnt = bpf_map_lookup_elem(&stats, &skey);
		if (cnt)
			*cnt += 1;
		return bpf_map_delete_elem(&store, &key);

	case OP_STATS:
		/* 用户态直接读 percpu stats map 获取详细统计 */
		return 0;

	default:
		return -ERR_INVAL;
	}
}
