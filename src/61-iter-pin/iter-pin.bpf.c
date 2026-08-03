// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 61-iter-pin: BPF 内核态 — iter/task 遍历所有进程。
 *
 * 此示例专门用于演示 bpftool iter pin + cat 工作流：
 *   bpftool iter pin ./iter-pin.bpf.o /sys/fs/bpf/my_task_iter
 *   cat /sys/fs/bpf/my_task_iter
 *   rm /sys/fs/bpf/my_task_iter
 *
 * 不需要用户态程序，BPF 程序直接输出到 seq_file，cat 即可读取。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if (task == NULL)
		return 0;

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "%-8s %-8s %-16s\n", "tgid", "pid", "comm");

	BPF_SEQ_PRINTF(seq, "%-8d %-8d %-16s\n",
		       task->tgid, task->pid, task->comm);

	return 0;
}
