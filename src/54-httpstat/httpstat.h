/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 54-httpstat: HTTP 流量统计示例共享定义。
 *
 * BPF 侧解析 HTTP 请求/响应，通过 ringbuf 发送结构化事件到用户态。
 * 用户态聚合统计：方法分布、状态码分布、URL 路径计数、源 IP Top N、字节数。
 */
#ifndef __HTTPSTAT_H
#define __HTTPSTAT_H

#define MAX_PATH_LEN 128

#define HTTP_UNKNOWN  0
#define HTTP_REQUEST  1
#define HTTP_RESPONSE 2

#define HTTP_GET     0
#define HTTP_POST    1
#define HTTP_PUT     2
#define HTTP_DELETE  3
#define HTTP_HEAD    4
#define HTTP_PATCH   5
#define HTTP_OTHER   6

#define HTTP_METHOD_COUNT 7

static const char * const http_method_names[HTTP_METHOD_COUNT] = {
	"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OTHER",
};

struct http_event {
	__u32 saddr;        /* 源 IP（网络字节序） */
	__u32 daddr;        /* 目的 IP（网络字节序） */
	__u16 sport;
	__u16 dport;
	__u8  type;         /* HTTP_REQUEST / HTTP_RESPONSE */
	__u8  method;       /* HTTP_GET / HTTP_POST / ...（请求时有效） */
	__u16 status;       /* 状态码（响应时有效，请求时为 0） */
	__u32 payload_len;  /* TCP payload 总长度 */
	__u32 path_len;     /* URL 路径实际长度 */
	char  path[MAX_PATH_LEN];
};

#endif /* __HTTPSTAT_H */
