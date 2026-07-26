/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 53-transparent-proxy: 透明代理示例共享定义。
 *
 * 场景：客户端 connect(127.0.0.1:8080) 被 cgroup/connect4 BPF 程序
 * 透明改写到 sidecar:15006，sidecar 查原始目的后回源到 server:8080。
 *
 * 透明性限制（v1）：未实现 cgroup/getpeername4，客户端调 getpeername()
 * 会看到 127.0.0.1:15006 而非原始 127.0.0.1:8080。curl/HTTP 不受影响。
 */
#ifndef __PROXY_H
#define __PROXY_H

#define SERVER_PORT     8080    /* 业务服务监听端口 */
#define SIDECAR_PORT    15006   /* sidecar 监听端口（Istio 惯例） */
#define LOCALHOST_IPV4  0x0100007FUL  /* 127.0.0.1 网络字节序 */

/* 专用子 cgroup，BPF 程序挂在此 cgroup，避免影响宿主其他进程 */
#define DEMO_CGROUP     "/sys/fs/cgroup/ebpf-proxy-demo"

/* orig_dst：connect4 保存的原始目的地址 */
struct orig_dst {
	__u32 ip4;    /* 网络字节序 */
	__u16 port;   /* 网络字节序 */
	__u16 pad;
};

/* conn_map 的 key：客户端源 IP + 源端口（sockops 桥接用） */
struct conn_key {
	__u32 ip;     /* 网络字节序 */
	__u16 port;   /* 网络字节序 */
	__u16 pad;
};

#endif /* __PROXY_H */
