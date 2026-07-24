/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 52-sk-lookup-proxy: L7 代理示例。
 *
 * 参考了 Cloudflare 的 sk_lookup 用例：一个代理进程接收多个端口的
 * 入站 TCP 连接，无需为每个端口 bind() 一个 socket。
 *
 * 共享定义：BPF 和用户态共用。
 */
#ifndef __SK_LOOKUP_PROXY_H
#define __SK_LOOKUP_PROXY_H

#define PROXY_PORT_START 8000   /* 代理端口范围起始 */
#define PROXY_PORT_END   8099   /* 代理端口范围结束 */
#define BACKEND_PORT     9000   /* 后端 HTTP 服务器端口 */

#endif /* __SK_LOOKUP_PROXY_H */
