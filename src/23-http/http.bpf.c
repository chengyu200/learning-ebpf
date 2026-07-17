// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
/*
 * 23-http: 内核态 socket filter BPF 程序
 *
 * 本程序挂载到 raw packet socket（AF_PACKET）上，每个经过指定网卡
 * 的数据包都会触发执行。程序逐层解析以太网→IP→TCP 协议头，
 * 提取五元组信息和 TCP payload 前若干字节（通常含 HTTP 请求行），
 * 通过 ring buffer 发送到用户态打印。
 *
 * 教学概念：
 * - socket filter 程序类型（SEC("socket")）
 * - __sk_buff 上下文：访问包的 protocol/pkt_type/ifindex 等元数据
 * - bpf_skb_load_bytes：按偏移从数据包中读取字节
 * - BPF_MAP_TYPE_RINGBUF：内核→用户态的事件传递通道
 *
 * 数据包在内核中的结构（从低层到高层）：
 *   [以太网头 14B][IP头 20B+][TCP头 20B+][payload...]
 *    ^- ETH_HLEN   ^- nhoff    ^- payload_offset
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "http.h"

/* IP 分片标志位（用于跳过分片包） */
#define IP_MF     0x2000   /* More Fragments 标志 */
#define IP_OFFSET 0x1FFF   /* 分片偏移掩码 */
#define IP_TCP    6        /* TCP 协议号 */
#define ETH_HLEN  14       /* 以太网头长度（字节） */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * ring buffer map：内核态写入事件，用户态轮询读取。
 * 256KB 容量足够缓冲短时间的包事件。
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/*
 * 检查 IP 包是否为分片包。
 * 分片包的 payload 不完整，无法解析 HTTP，需要跳过。
 *
 * @skb   数据包上下文
 * @nhoff IP 头在数据包中的起始偏移（= ETH_HLEN = 14）
 * @return 非零=是分片包，0=非分片包
 */
static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	/* 从 IP 头中读取 frag_off 字段（2 字节，位于 IP 头偏移 6） */
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off),
			   &frag_off, 2);
	/* 网络字节序转主机字节序 */
	frag_off = __bpf_ntohs(frag_off);
	/* 如果 MF 标志置位或分片偏移非零，说明是分片包 */
	return frag_off & (IP_MF | IP_OFFSET);
}

/*
 * socket filter 主函数：每个数据包都会调用。
 *
 * @skb  内核提供的 __sk_buff 上下文，包含包的元数据
 *       （protocol, pkt_type, ifindex, data, data_end 等）
 * @return 0（socket filter 的返回值不影响包的接收，
 *         包始终会被传递到协议栈，这里只做旁路观察）
 */
SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct so_event *e;
	__u8 verlen;           /* IP 头第一个字节：高4位=version, 低4位=ihl */
	__u16 proto;
	__u32 nhoff = ETH_HLEN;  /* IP 头的起始偏移 = 以太网头长度 14 */
	__u32 ip_proto = 0;      /* IP 协议号 */
	__u32 tcp_hdr_len = 0;
	__u16 tlen;              /* IP 总长度（网络字节序） */
	__u32 payload_offset = 0;
	__u32 payload_length = 0;
	__u8 hdr_len;            /* IP 头长度（以 4 字节为单位） */

	/* ── 第一层过滤：只处理 IPv4 包 ──
	 * skb->protocol 存储以太网帧的 EtherType：
	 *   0x0800 = ETH_P_IP (IPv4)
	 * 注意：__bpf_ntohs 将网络字节序转主机字节序用于比较 */
	if (skb->protocol != __bpf_ntohs(0x0800 /* ETH_P_IP */))
		return 0;

	/* ── 在 ring buffer 中预留事件空间 ──
	 * 即使后续发现不是 TCP 包，也会提交（填零的部分），
	 * 这样简化了 BPF 程序的控制流。 */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* 填充包元数据 */
	e->pkt_type = skb->pkt_type;  /* 包方向：PACKET_HOST(收) / PACKET_OUTGOING(发) */
	e->ifindex = skb->ifindex;    /* 收包网卡索引 */

	/* ── 第二层过滤：只处理 TCP 包 ──
	 * 从 IP 头读取 protocol 字段（1 字节，偏移 9） */
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol),
			   &ip_proto, 1);
	if (ip_proto != IP_TCP)
		goto out;  /* 非 TCP 包（如 ICMP/UDP），直接提交空事件 */

	/* 跳过分片包：分片 payload 不完整 */
	if (ip_is_fragment(skb, nhoff))
		goto out;

	/* ── 提取 IP 地址 ──
	 * 从 IP 头读取源地址（偏移 12）和目的地址（偏移 16），各 4 字节 */
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr),
			   &e->src_addr, 4);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr),
			   &e->dst_addr, 4);

	/* 读取 IP 总长度（包含 IP 头 + 数据，网络字节序） */
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len),
			   &tlen, sizeof(tlen));
	e->ports = 0;

	/* ── 计算 IP 头长度 ──
	 * IP 头第一个字节：高 4 位 = IP 版本(4), 低 4 位 = IHL(头长/4)
	 * IHL(Internet Header Length) 以 4 字节为单位，通常为 5（即 20 字节）
	 * 注意：iphdr.ihl 是位域，不能用 offsetof，所以直接读第一个字节 */
	bpf_skb_load_bytes(skb, nhoff, &verlen, 1);
	hdr_len = verlen & 0x0f;          /* 取低 4 位得到 IHL */
	tcp_hdr_len = hdr_len * 4;        /* IP 头实际字节数 */

	/* payload 起始偏移 = 以太网头 + IP头 + TCP头(估14≈20，但这里用14作估算)
	 * 注意：这里 +14 是 TCP 头最小长度的估算值，实际 TCP 头长度可能不同 */
	payload_offset = ETH_HLEN + hdr_len * 4 + 14;

	/* ── 提取 TCP 端口 ──
	 * TCP 头紧跟 IP 头之后，前 4 字节 = 源端口(2B) + 目的端口(2B) */
	bpf_skb_load_bytes(skb, nhoff + hdr_len * 4, &e->port16, 4);
	e->port16[0] = __bpf_ntohs(e->port16[0]);  /* 源端口转主机字节序 */
	e->port16[1] = __bpf_ntohs(e->port16[1]);  /* 目的端口转主机字节序 */
	e->ip_proto = ip_proto;

	/* ── 提取 TCP payload ──
	 * payload 长度 = IP总长度 - IP头长度 - TCP头长度(估20)
	 * 这是估算值（TCP 头实际长度可能 >20），对 HTTP 来说足够 */
	payload_length = __bpf_ntohs(tlen) - hdr_len * 4 - 20;

	/* 限制 payload 捕获长度不超过缓冲区大小 */
	if (payload_length > MAX_BUF_SIZE)
		payload_length = MAX_BUF_SIZE;

	/* 如果有 payload 数据，从数据包中读取 */
	if (payload_length > 0) {
		bpf_skb_load_bytes(skb, payload_offset, e->payload,
				payload_length);
	}
	e->payload_length = payload_length;

out:
	/* 提交事件到 ring buffer，用户态将收到并处理 */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
