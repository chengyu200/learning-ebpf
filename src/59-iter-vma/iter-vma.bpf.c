// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 59-iter-vma: BPF 内核态 — iter/task_vma 遍历进程虚拟内存区域。
 *
 * SEC("iter/task_vma") 对每个 (task, vma) 组合调用一次。
 * 输出 pid + vma 范围 + 权限标志，类似 /proc/<pid>/maps。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

int target_pid = 0;

SEC("iter/task_vma")
int dump_task_vma(struct bpf_iter__task_vma *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct vm_area_struct *vma = ctx->vma;
	char flags[5] = "----";

	if (task == NULL || vma == NULL)
		return 0;

	if (target_pid != 0 && task->tgid != target_pid)
		return 0;

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "%-8s %-18s %-18s %s\n",
			       "pid", "start", "end", "perms");

	/* 构建权限字符串 */
	if (vma->vm_flags & 0x1) flags[0] = 'r';
	if (vma->vm_flags & 0x2) flags[1] = 'w';
	if (vma->vm_flags & 0x4) flags[2] = 'x';
	flags[3] = 'p';

	BPF_SEQ_PRINTF(seq, "%-8d %-18lx %-18lx %s\n",
		       task->tgid,
		       (unsigned long)vma->vm_start,
		       (unsigned long)vma->vm_end,
		       flags);

	return 0;
}
