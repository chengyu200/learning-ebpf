/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 71-netkit: Netkit 虚拟设备对 BPF 过滤示例。
 *
 * 共享定义。
 */
#ifndef __NETKIT_H
#define __NETKIT_H

/* per-CPU 统计数据 */
struct stats {
	__u64 packets;   /* 总包数 */
	__u64 bytes;     /* 总字节数 */
	__u64 dropped;   /* 丢弃的包数 */
};

#endif /* __NETKIT_H */
