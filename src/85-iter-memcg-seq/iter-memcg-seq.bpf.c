// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 85-iter-memcg-seq: BPF 内核态 — iter/cgroup 遍历 cgroup 层级，
 * 从每个 cgroup 获取 mem_cgroup 并输出内存使用信息。
 *
 * 方案 A：用 SEC("iter/cgroup") 遍历所有 cgroup，
 *         从 cgroup->subsys[memory_cgrp_id] 获取 mem_cgroup 的 css，
 *         container_of(css, mem_cgroup, css) 得到 mem_cgroup，
 *         读取 memory.usage / memory.max / memory.high / swap.usage 并输出到 seq_file。
 *
 * 与 84-iter-memcg（方案 B）的区别：
 *   - 84: bpf_get_root_mem_cgroup() + bpf_for_each(css) 直接遍历 mem_cgroup 树
 *   - 85: SEC("iter/cgroup") 遍历 cgroup 层级，从每个 cgroup 获取 mem_cgroup
 *   - 85 不需要引用管理（iter/cgroup 管理生命周期）
 *   - 85 用 BPF_SEQ_PRINTF 输出（vs ringbuf）
 *
 * 教学概念：
 * - SEC("iter/cgroup") + bpf_program__attach_iter
 * - cgroup->subsys[memory_cgrp_id] → css → container_of → mem_cgroup
 * - BPF_SEQ_PRINTF 输出到 seq_file
 * - kernfs_node 路径遍历（同 62-iter-cgroup）
 * - BPF_CORE_READ 读取 atomic_long_t counter 字段
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* memory_cgrp_id = 4（内核 enum，cgroup v2 中 memory 子系统的 ID） */
#define MEMORY_CGRP_ID 4

/* page_counter 中 max/high 的最大值，表示未设置限制 */
#define PAGE_COUNTER_MAX 2251799813685247ULL

/* page 大小 = 4096 字节，换算 KB = page_count * 4096 / 1024 = page_count * 4 */
#define PAGE_TO_KB(pages) ((__u64)(pages) * 4)

SEC("iter/cgroup")
int dump_memcg(struct bpf_iter__cgroup *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct cgroup *cg = ctx->cgroup;
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memcg;
	struct kernfs_node *kn;
	struct kernfs_node *nodes[16];
	char name[64];
	int depth = 0;
	int level;
	__u64 memcg_id, memory_usage, memory_max, memory_high, swap_usage;

	if (cg == NULL)
		return 0;

	/* 从 cgroup 获取 mem_cgroup 的 css
	 * cgroup->subsys[memory_cgrp_id] 指向 mem_cgroup.css */
	css = BPF_CORE_READ(cg, subsys[MEMORY_CGRP_ID]);
	if (!css)
		return 0;

	/* container_of：css 是 mem_cgroup 的第一个字段 */
	memcg = container_of(css, struct mem_cgroup, css);

	/* 读取 mem_cgroup 信息
	 * usage 是 page 个数（atomic_long_t counter），换算为 KB
	 * max/high 是 page 个数或 PAGE_COUNTER_MAX（无限制），换算为 KB 或输出 "max" */
	memcg_id = BPF_CORE_READ(css, serial_nr);
	memory_usage = BPF_CORE_READ(memcg, memory.usage.counter);
	memory_max = BPF_CORE_READ(memcg, memory.max);
	memory_high = BPF_CORE_READ(memcg, memory.high);
	swap_usage = BPF_CORE_READ(memcg, swap.usage.counter);
	level = BPF_CORE_READ(cg, level);

	/* 表头（仅第一次输出） */
	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "%-10s %-6s %-12s %-12s %-12s %-12s %s\n",
			       "id", "level", "memory(KB)", "max(KB)", "high(KB)", "swap(KB)", "path");

	/* 输出 id + level + memory(KB) */
	BPF_SEQ_PRINTF(seq, "%-10llu %-6d %-12llu ",
		       memcg_id, level, PAGE_TO_KB(memory_usage));

	/* max: PAGE_COUNTER_MAX 输出 "max"，否则换算 KB */
	if (memory_max == PAGE_COUNTER_MAX)
		BPF_SEQ_PRINTF(seq, "%-12s ", "max");
	else
		BPF_SEQ_PRINTF(seq, "%-12llu ", PAGE_TO_KB(memory_max));

	/* high: PAGE_COUNTER_MAX 输出 "max"，否则换算 KB */
	if (memory_high == PAGE_COUNTER_MAX)
		BPF_SEQ_PRINTF(seq, "%-12s ", "max");
	else
		BPF_SEQ_PRINTF(seq, "%-12llu ", PAGE_TO_KB(memory_high));

	/* swap(KB) */
	BPF_SEQ_PRINTF(seq, "%-12llu ", PAGE_TO_KB(swap_usage));

	/* 构建 cgroup 完整路径：沿 kernfs_node->__parent 向上遍历 */
	kn = BPF_CORE_READ(cg, kn);
	if (!kn) {
		BPF_SEQ_PRINTF(seq, "(unknown)\n");
		return 0;
	}

	for (int i = 0; i < 16; i++) {
		if (kn == NULL)
			break;
		nodes[i] = kn;
		depth = i + 1;
		kn = BPF_CORE_READ(kn, __parent);
	}

	/* 从根到叶输出路径（反序） */
	int printed = 0;
	for (int i = 15; i >= 0; i--) {
		if (i >= depth)
			continue;

		long ret = bpf_probe_read_kernel_str(name, sizeof(name),
						    BPF_CORE_READ(nodes[i], name));
		if (ret > 1) {
			BPF_SEQ_PRINTF(seq, "/%s", name);
			printed = 1;
		}
	}

	if (!printed)
		BPF_SEQ_PRINTF(seq, "/");

	BPF_SEQ_PRINTF(seq, "\n");

	return 0;
}
