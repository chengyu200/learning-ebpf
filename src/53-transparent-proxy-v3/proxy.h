/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 53-transparent-proxy-v3: 透明代理示例共享定义（sk_lookup 入流量 + connect4 出流量）。
 *
 * v3 架构：
 *   - 入流量：sk_lookup（netns 级）拦截 VIRTUAL_PORT → bpf_sk_assign 到 sidecar
 *     外部 client 无需在 cgroup 内，curl 即可被透明劫持
 *   - 出流量：cgroup/connect4（cgroup 级）仅劫持 server PID 的出连接
 *   - server 监听 SERVER_PORT（:9000），sk_lookup 不拦截 → 无回环
 *
 * 透明性限制（v3）：未实现 cgroup/getpeername4。
 */
#ifndef __PROXY_H
#define __PROXY_H

#define VIRTUAL_PORT    8080    /* 外部 client 访问的虚拟端口（sk_lookup 拦截） */
#define SERVER_PORT     9000    /* server 实际监听端口（sidecar 回源到此，sk_lookup 不拦截） */
#define SIDECAR_PORT    15006   /* sidecar 监听端口 */
#define LOCALHOST_IPV4  0x0100007FUL  /* 127.0.0.1 网络字节序 */

/* v2/v3 外部服务：在 bpfns netns 内，通过 veth 对访问 */
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
