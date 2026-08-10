// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 76-tc-tcx: TC/TCX 流量统计。
 *
 * 四个程序对比 tc/ 和 tcx/ 两种 SEC 写法：
 *   ① SEC("tc/ingress")  — ingress 流量统计
 *   ② SEC("tc/egress")   — egress 流量统计
 *   ③ SEC("tcx/ingress") — ingress 流量统计（与 tc/ingress 完全等价）
 *   ④ SEC("tcx/egress")  — egress 流量统计（与 tc/egress 完全等价）
 *
 * 关键发现：tc/ingress 和 tcx/ingress 是完全等价的别名！
 * libbpf source: SEC_DEF("tc/ingress", SCHED_CLS, BPF_TCX_INGRESS, SEC_NONE) - alias for tcx
 * Both use the same attach type (BPF_TCX_INGRESS) and same API (bpf_program__attach_tcx).
 *
 * 对比三种 TC SEC 写法：
 *   SEC("tc")         - legacy, manual bpf_tc_hook_create + bpf_tc_attach (see 20-tc)
 *   SEC("tc/ingress")  - new, bpf_program__attach_tcx (alias for tcx/ingress)
 *   SEC("tcx/ingress") - new, bpf_program__attach_tcx
 *
 * 返回值（TCX action，enum tcx_action_base）：
 *   TCX_PASS  (0)  = 放行，停止 TCX 链
 *   TCX_NEXT  (-1) = 继续链（传递给下一个 TCX 程序，见 78-tcx-chain）
 *   TCX_DROP  (2)  = 丢弃，停止链
 *
 * 注意：TCX 使用自己的返回值枚举，不是传统 TC 的 TC_ACT_*。
 *   TCX_PASS (0) = TC_ACT_OK (0)，数值相同但语义更准确。
 *   TCX_NEXT (-1) != TC_ACT_PIPE (3)，继续链必须用 TCX_NEXT。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tc_tcx.h"

#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "GPL";

/* per-CPU 包计数（4 个 slot 对应 4 个程序） */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} pkt_count SEC(".maps");

/* per-CPU 字节计数 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} byte_count SEC(".maps");

#define IDX_TC_INGRESS  0
#define IDX_TC_EGRESS   1
#define IDX_TCX_INGRESS 2
#define IDX_TCX_EGRESS  3

static __always_inline int count_packet(struct __sk_buff *skb, __u32 idx)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u64 *cnt, *bytes;

	if ((void *)(eth + 1) > data_end)
		return TCX_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TCX_PASS;

	cnt = bpf_map_lookup_elem(&pkt_count, &idx);
	bytes = bpf_map_lookup_elem(&byte_count, &idx);
	if (cnt)
		(*cnt)++;
	if (bytes)
		*bytes += skb->len;

	return TCX_PASS;
}

/* ① tc/ingress — 统计入口 IPv4 包 */
SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb)
{
	return count_packet(skb, IDX_TC_INGRESS);
}

/* ② tc/egress — 统计出口 IPv4 包 */
SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
	return count_packet(skb, IDX_TC_EGRESS);
}

/* ③ tcx/ingress — 与 tc/ingress 完全等价（别名） */
SEC("tcx/ingress")
int tcx_ingress(struct __sk_buff *skb)
{
	return count_packet(skb, IDX_TCX_INGRESS);
}

/* ④ tcx/egress — 与 tc/egress 完全等价（别名） */
SEC("tcx/egress")
int tcx_egress(struct __sk_buff *skb)
{
	return count_packet(skb, IDX_TCX_EGRESS);
}
