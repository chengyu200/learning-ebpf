/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2022 Jacky Yin */
/*
 * 23-http: 通过 socket filter 捕获 HTTP 请求
 *
 * 本文件是内核态 BPF 程序，挂载到 raw packet socket 上。
 * 每当网卡收到一个数据包，内核就会调用这个 BPF 程序。
 * 程序解析以太网→IP→TCP 各层协议头，提取源/目的地址、端口和
 * payload 前若干字节（通常包含 HTTP 请求行），通过 ring buffer
 * 发送到用户态。
 */
#ifndef __SOCKFILTER_H
#define __SOCKFILTER_H

/* payload 最大捕获长度（字节）
 * 128 字节足够捕获 HTTP 请求行（GET / HTTP/1.1 + Host 头等） */
#define MAX_BUF_SIZE 128

/* 从 BPF 程序发送到用户态的事件结构体 */
struct so_event {
	__be32 src_addr;            /* 源 IPv4 地址（网络字节序） */
	__be32 dst_addr;            /* 目的 IPv4 地址（网络字节序） */
	union {                     /* 源端口 + 目的端口（联合体便于整体读写） */
		__be32 ports;       /* 4 字节整体 = 源端口(2B) + 目的端口(2B) */
		__be16 port16[2];   /* 拆开访问：port16[0]=源端口, port16[1]=目的端口 */
	};
	__u32 ip_proto;             /* IP 协议号：6=TCP, 17=UDP */
	__u32 pkt_type;             /* 包类型：PACKET_HOST(0)=发给本机, PACKET_OUTGOING(4)=本机发出 */
	__u32 ifindex;              /* 网卡索引（可通过 if_indextoname 转为网卡名） */
	__u32 payload_length;       /* 实际捕获的 payload 字节数 */
	__u8 payload[MAX_BUF_SIZE]; /* payload 数据（HTTP 请求行/响应头等） */
};

#endif /* __SOCKFILTER_H */
