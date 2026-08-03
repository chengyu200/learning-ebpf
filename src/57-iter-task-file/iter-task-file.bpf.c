// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 57-iter-task-file: BPF 内核态 — iter/task_file 遍历进程打开的文件。
 *
 * SEC("iter/task_file") 程序对每个 (task, fd) 组合调用一次。
 * 用户态可通过 bpf_iter_attach_opts 参数化过滤指定 PID。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* 可选：全局变量过滤（attach_opts 之外的另一种过滤方式） */
int target_pid = 0;

SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	__u32 fd = ctx->fd;

	if (task == NULL || file == NULL)
		return 0;

	/* 全局变量过滤（target_pid=0 表示不过滤） */
	if (target_pid != 0 && task->tgid != target_pid)
		return 0;

	/* 第一行打印表头 */
	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "%-8s %-8s %-16s %-8s %-16s\n",
			       "tgid", "pid", "comm", "fd", "file_ops");

	BPF_SEQ_PRINTF(seq, "%-8d %-8d %-16s %-8d %lx\n",
		       task->tgid, task->pid, task->comm, fd, (long)file->f_op);

	return 0;
}
