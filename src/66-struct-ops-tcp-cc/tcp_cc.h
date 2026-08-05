/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 66-struct-ops-tcp-cc: 用 BPF struct_ops 实现 TCP 拥塞控制算法。
 *
 * 共享定义：事件结构体 + CC 名称常量。
 */
#ifndef __TCP_CC_H
#define __TCP_CC_H

#define CC_NAME "bpf_reno_trace"

#define EV_INIT    1
#define EV_CWND    2
#define EV_STATE   3
#define EV_RELEASE 4

struct cc_event {
	__u8  type;
	__u8  state;
	__u8  pad[2];
	__u32 pid;
	__u32 cwnd;
	__u32 ssthresh;
	__u64 ts_ns;
};

#endif /* __TCP_CC_H */
