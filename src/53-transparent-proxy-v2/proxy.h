/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 53-transparent-proxy-v2: 透明代理示例共享定义（含出流量劫持）。
 *
 * v1: 入流量劫持 — 客户端 connect(127.0.0.1:8080) → sidecar:15006
 * v2: + 出流量劫持 — server connect(192.168.99.2:9090) → sidecar:15006
 *     仅劫持 server PID 的出连接，其他进程（client 等）出连接放行。
 *
 * 透明性限制（v2）：未实现 cgroup/getpeername4。
 */
#ifndef __PROXY_H
#define __PROXY_H

#define SERVER_PORT     8080    /* 业务服务监听端口 */
#define SIDECAR_PORT    15006   /* sidecar 监听端口（Istio 惯例） */
#define LOCALHOST_IPV4  0x0100007FUL  /* 127.0.0.1 网络字节序 */

/* v2 外部服务：在 bpfns netns 内，通过 veth 对访问 */
#define EXT_SERVER_IP   "192.168.99.2"
#define EXT_SERVER_IPV4 0x020363C0UL  /* 192.168.99.2 网络字节序 */
#define EXT_SERVER_PORT 9090

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
