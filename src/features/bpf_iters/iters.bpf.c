// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* features/bpf_iters: BPF iterators for exporting kernel data.
 *
 * A bpf_iter program iterates over tasks and prints pid/comm for each,
 * demonstrating the iter program type and seq_file output.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if (task == NULL)
		return 0;

	BPF_SEQ_PRINTF(seq, "pid=%d comm=%s\n", task->pid, task->comm);
	return 0;
}
