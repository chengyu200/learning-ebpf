// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 54-httpstat: BPF 内核态 — socket filter 捕获 HTTP 流量并解析。
 *
 * 捕获机制：AF_PACKET raw socket + SO_ATTACH_BPF（与 23-http 一致）
 * 解析流程：Ethernet → IP → TCP → payload
 *   payload 判断：
 *     "GET "/"POST " 等 → 请求：提取 method + path
 *     "HTTP/"           → 响应：提取 status code
 *     其他              → 忽略
 * 输出：ringbuf 发送 http_event 到用户态
 *
 * 相比 23-http 的改进：
 *   - 正确解析 TCP data offset（而非硬编码 14 字节）
 *   - 用 bpf_strncmp 识别 HTTP 方法
 *   - 提取 URL path（有界循环）
 *   - 解析响应状态码
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "httpstat.h"

#define ETH_P_IP   0x0800
#define IP_PROTO_TCP 6
#define ETH_HLEN   14

/* payload 最大读取长度：足够覆盖 HTTP 请求行 + 部分头 */
#define MAX_PAYLOAD_READ 160

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off),
			   &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (0x2000 | 0x1FFF);
}

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct http_event *e;
	__u8 verlen;
	__u16 ip_tot_len;
	__u8 ip_proto;
	__u32 nhoff = ETH_HLEN;
	__u32 ip_hdr_len;
	__u32 tcp_offset;
	__u8 doff_byte;
	__u32 tcp_hdr_len;
	__u32 payload_offset;
	__u32 payload_length;
	char buf[MAX_PAYLOAD_READ];
	__u32 to_read;
	int method = -1;
	int path_start = 0;
	int path_len = 0;
	__u16 status = 0;
	__u8 type = 0;

	/* 仅处理 IPv4 */
	if (skb->protocol != __bpf_ntohs(ETH_P_IP))
		return 0;

	/* 读取 IP 头：protocol + IHL + tot_len */
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol),
			   &ip_proto, 1);
	if (ip_proto != IP_PROTO_TCP)
		return 0;

	if (ip_is_fragment(skb, nhoff))
		return 0;

	bpf_skb_load_bytes(skb, nhoff, &verlen, 1);
	ip_hdr_len = (verlen & 0x0f) * 4;
	if (ip_hdr_len < 20)
		return 0;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len),
			   &ip_tot_len, 2);
	ip_tot_len = __bpf_ntohs(ip_tot_len);

	/* TCP 头偏移 */
	tcp_offset = nhoff + ip_hdr_len;

	/* 正确解析 TCP data offset（修复 23-http 硬编码问题） */
	bpf_skb_load_bytes(skb, tcp_offset + 12, &doff_byte, 1);
	tcp_hdr_len = (doff_byte >> 4) * 4;
	if (tcp_hdr_len < 20)
		return 0;

	payload_offset = tcp_offset + tcp_hdr_len;
	payload_length = ip_tot_len - ip_hdr_len - tcp_hdr_len;
	if (payload_length == 0 || payload_length > 65535)
		return 0;

	/* 读取 payload 到栈缓冲区 */
	to_read = payload_length;
	if (to_read > MAX_PAYLOAD_READ)
		to_read = MAX_PAYLOAD_READ;
	if (to_read < 4)
		return 0;  /* 太短无法识别 HTTP 方法 */

	if (bpf_skb_load_bytes(skb, payload_offset, buf, to_read) < 0)
		return 0;

	/* HTTP 请求方法识别 */
	if (to_read >= 4 && bpf_strncmp(buf, 4, "GET ") == 0) {
		method = HTTP_GET;
		path_start = 4;
		type = HTTP_REQUEST;
	} else if (to_read >= 5 && bpf_strncmp(buf, 5, "POST ") == 0) {
		method = HTTP_POST;
		path_start = 5;
		type = HTTP_REQUEST;
	} else if (to_read >= 4 && bpf_strncmp(buf, 4, "PUT ") == 0) {
		method = HTTP_PUT;
		path_start = 4;
		type = HTTP_REQUEST;
	} else if (to_read >= 7 && bpf_strncmp(buf, 7, "DELETE ") == 0) {
		method = HTTP_DELETE;
		path_start = 7;
		type = HTTP_REQUEST;
	} else if (to_read >= 5 && bpf_strncmp(buf, 5, "HEAD ") == 0) {
		method = HTTP_HEAD;
		path_start = 5;
		type = HTTP_REQUEST;
	} else if (to_read >= 6 && bpf_strncmp(buf, 6, "PATCH ") == 0) {
		method = HTTP_PATCH;
		path_start = 6;
		type = HTTP_REQUEST;
	} else if (to_read >= 5 && bpf_strncmp(buf, 5, "HTTP/") == 0) {
		/* HTTP 响应："HTTP/1.1 200 OK\r\n" */
		type = HTTP_RESPONSE;
		if (to_read >= 12) {
			__u8 c0 = buf[9] - '0';
			__u8 c1 = buf[10] - '0';
			__u8 c2 = buf[11] - '0';
			if (c0 <= 9 && c1 <= 9 && c2 <= 9)
				status = c0 * 100 + c1 * 10 + c2;
		}
	} else {
		/* 非 HTTP 流量 */
		return 0;
	}

	/* 其他请求方法（OPTIONS/TRACE/CONNECT 等） */
	if (type == HTTP_REQUEST && method < 0) {
		method = HTTP_OTHER;
		path_start = 0;
		/* 尝试找到第一个空格作为 path_start */
		for (int i = 0; i < 16 && i < (int)to_read; i++) {
			if (buf[i] == ' ') {
				path_start = i + 1;
				break;
			}
		}
	}

	/* 提取 URL path（有界循环） */
	if (type == HTTP_REQUEST && path_start > 0) {
		for (int i = 0; i < MAX_PATH_LEN && (path_start + i) < (int)to_read; i++) {
			char c = buf[path_start + i];
			if (c == ' ' || c == '\r' || c == '\n' || c == '\0' ||
			    c == '?')
				break;
			path_len = i + 1;
		}
	}

	/* 构建事件并发送 */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* 读取 IP 地址 */
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr),
			   &e->saddr, 4);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr),
			   &e->daddr, 4);

	/* 读取端口 */
	bpf_skb_load_bytes(skb, tcp_offset, &e->sport, 2);
	bpf_skb_load_bytes(skb, tcp_offset + 2, &e->dport, 2);
	e->sport = __bpf_ntohs(e->sport);
	e->dport = __bpf_ntohs(e->dport);

	e->type = type;
	e->method = (method >= 0) ? method : HTTP_OTHER;
	e->status = status;
	e->payload_len = payload_length;
	e->path_len = path_len;

	/* 复制 path */
	if (path_len > 0) {
		__u32 copy_len = path_len;
		if (copy_len > MAX_PATH_LEN)
			copy_len = MAX_PATH_LEN;
		for (__u32 i = 0; i < copy_len; i++)
			e->path[i] = buf[path_start + i];
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
