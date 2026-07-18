/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 42-xdp-loadbalancer: 共享头文件
 *
 * 定义后端服务器信息和最大后端数量，供 BPF 程序和用户态程序共用。
 */
#ifndef __XDP_LB_H
#define __XDP_LB_H

/* 最大后端服务器数量 */
#define MAX_BACKENDS 8

/* 后端服务器信息
 * 用户态在加载 BPF 程序前将后端列表填入 array map；
 * BPF 程序根据哈希结果查询此 map 获取目标后端。 */
struct backend {
	__u32 addr;       /* 后端 IPv4 地址（网络字节序，即大端） */
	__u8 mac[6];      /* 后端 MAC 地址（用于重写以太网目的地址） */
};

#endif
