/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 53-transparent-proxy-v4: 透明代理示例共享定义。
 *
 * v4 关键变化：端口一致！server 监听 0.0.0.0:8080（与用户访问端口相同）。
 *   - 入流量：sk_lookup 拦截 :8080 → bpf_sk_assign 到 sidecar
 *   - 防回环：sk_lookup 中用 PID 排除（sidecar 自身 connect 跳过）
 *   - 出流量：cgroup/connect4 仅劫持 server PID
 *
 * 透明性限制（v4）：未实现 cgroup/getpeername4。
 */
#ifndef __PROXY_H
#define __PROXY_H

#define VIRTUAL_PORT    8080    /* 用户访问端口（sk_lookup 拦截） */
#define SERVER_PORT     8080    /* server 实际监听端口（与 VIRTUAL_PORT 一致） */
#define SIDECAR_PORT    15006   /* sidecar 监听端口 */
#define LOCALHOST_IPV4  0x0100007FUL  /* 127.0.0.1 网络字节序 */

/* 外部服务：在 bpfns netns 内，通过 veth 对访问 */
#define EXT_SERVER_IP   "192.168.99.2"
#define EXT_SERVER_IPV4 0x020363C0UL  /* 192.168.99.2 网络字节序 */
#define EXT_SERVER_PORT 9090

/* 专用子 cgroup，BPF 程序挂在此 cgroup，避免影响宿主其他进程 */
#define DEMO_CGROUP     "/sys/fs/cgroup/ebpf-proxy-demo"

/* orig_dst：connect4 保存的原始目的地址（仅出流量） */
struct orig_dst {
	__u32 ip4;    /* 网络字节序 */
	__u16 port;   /* 网络字节序 */
	__u16 pad;
};

/* conn_map 的 key：发起方源 IP + 源端口（sockops 桥接用，仅出流量） */
struct conn_key {
	__u32 ip;     /* 网络字节序 */
	__u16 port;   /* 网络字节序 */
	__u16 pad;
};

#endif /* __PROXY_H */
