/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 67-syscall-prog: BPF syscall RPC 键值存储共享定义。
 *
 * 用户态通过 BPF_PROG_RUN 传入 rpc_req，BPF 程序操作内核 HASH map 并返回结果。
 */
#ifndef __RPC_KV_H
#define __RPC_KV_H

#define OP_PUT    1
#define OP_LOOKUP 2
#define OP_DELETE 3
#define OP_STATS  4

#define ERR_NOENT 2
#define ERR_INVAL 22

#define STATS_PUT    0
#define STATS_LOOKUP 1
#define STATS_DELETE 2
#define STATS_COUNT  3

struct rpc_req {
	__u32 op;
	__u32 key;
	__u64 value;
};

#endif /* __RPC_KV_H */
