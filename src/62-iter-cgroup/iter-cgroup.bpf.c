// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 62-iter-cgroup: BPF 内核态 — iter/cgroup 遍历 cgroup 层级。
 *
 * 输出每个 cgroup 的 id、路径名、level、子节点数、进程数。
 * 类似 cat /sys/fs/cgroup/cgroup.subtree_status，但用 BPF iterator 实现。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("iter/cgroup")
int dump_cgroup(struct bpf_iter__cgroup *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct cgroup *cg = ctx->cgroup;
	struct kernfs_node *kn;
	char name[128] = {};
	int level, nr_desc;
	__u64 id;

	if (cg == NULL)
		return 0;

	kn = BPF_CORE_READ(cg, kn);
	if (kn == NULL)
		return 0;

	/* 用 bpf_probe_read_kernel_str 读取内核字符串到栈缓冲区 */
	bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(kn, name));

	level = BPF_CORE_READ(cg, level);
	nr_desc = BPF_CORE_READ(cg, nr_descendants);
	id = BPF_CORE_READ(kn, id);

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "%-8s %-6s %-8s %s\n",
			       "id", "level", "nrdesc", "name");

	BPF_SEQ_PRINTF(seq, "%-8llu %-6d %-8d %s\n",
		       id, level, nr_desc, name);

	return 0;
}
