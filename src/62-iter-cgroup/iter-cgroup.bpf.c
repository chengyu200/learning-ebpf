// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 62-iter-cgroup: BPF 内核态 — iter/cgroup 遍历 cgroup 层级。
 *
 * 输出每个 cgroup 的 id、完整路径、level、子节点数。
 * 通过沿 kernfs_node->__parent 向上遍历收集路径组件，
 * 然后从根到叶顺序打印。
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
	struct kernfs_node *nodes[16];
	int depth = 0;
	char name[64];
	int level, nr_desc;
	__u64 id;

	if (cg == NULL)
		return 0;

	kn = BPF_CORE_READ(cg, kn);
	if (kn == NULL)
		return 0;

	id = BPF_CORE_READ(kn, id);
	level = BPF_CORE_READ(cg, level);
	nr_desc = BPF_CORE_READ(cg, nr_descendants);

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "%-8s %-6s %-8s %s\n",
			       "id", "level", "nrdesc", "path");

	BPF_SEQ_PRINTF(seq, "%-8llu %-6d %-8d ", id, level, nr_desc);

	/* Walk up kernfs hierarchy, collecting node pointers.
	 * kernfs_node has __parent field; root cgroup's parent is NULL.
	 * Max 16 levels — sufficient for typical cgroup hierarchies.
	 */
	for (int i = 0; i < 16; i++) {
		if (kn == NULL)
			break;
		nodes[i] = kn;
		depth = i + 1;
		kn = BPF_CORE_READ(kn, __parent);
	}

	/* Print path: root to leaf (reverse order) */
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
