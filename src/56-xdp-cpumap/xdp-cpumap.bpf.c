// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 56-xdp-cpumap: BPF 内核态 — XDP CPUMAP 跨 CPU 重定向。
 *
 * 两个 XDP 程序：
 *   ① SEC("xdp") xdp_redirect_cpu — ingress 程序，在接收 CPU 上运行
 *      - 计数 ingress 包
 *      - bpf_redirect_map 重定向到 CPU ^ 1
 *
 *   ② SEC("xdp/cpumap") xdp_cpumap_prog — cpumap 程序，在目标 CPU 上运行
 *      - 计数 cpumap 处理的包
 *      - return XDP_PASS 放行到协议栈
 *
 * CPUMAP 重定向需要 native XDP（DRV mode），SKB mode 下 bpf_redirect_map
 * 到 cpumap 可能不生效。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "xdp-cpumap.h"

char LICENSE[] SEC("license") = "GPL";

/* CPUMAP: key=CPU id, value=bpf_cpumap_val（用户态填充 qsize + prog fd） */
struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(max_entries, MAX_CPUS);
	__type(key, __u32);
	__type(value, struct bpf_cpumap_val);
} cpumap SEC(".maps");

/* per-CPU ingress 计数 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rx_cnt SEC(".maps");

/* per-CPU cpumap 处理计数 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} cpumap_cnt SEC(".maps");

/* ① ingress 程序：重定向包到另一个 CPU */
SEC("xdp")
int xdp_redirect_cpu(struct xdp_md *ctx)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 target = cpu ^ 1;
	__u32 key = 0;
	__u64 *cnt;

	/* ingress 计数 */
	cnt = bpf_map_lookup_elem(&rx_cnt, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);

	/* 重定向到目标 CPU；flags 低 2 位 = XDP_PASS(2) 作为 redirect 失败的回退 */
	return bpf_redirect_map(&cpumap, target, XDP_PASS);
}

/* ② cpumap 程序：在目标 CPU 上运行 */
SEC("xdp/cpumap")
int xdp_cpumap_prog(struct xdp_md *ctx)
{
	__u32 key = 0;
	__u64 *cnt;

	/* cpumap 处理计数 */
	cnt = bpf_map_lookup_elem(&cpumap_cnt, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);

	return XDP_PASS;
}
