// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 1-helloworld: minimal eBPF program.
 *
 * Kernel side: attach a tracepoint to sys_enter_execve and print a greeting
 * through the kernel trace pipe (bpf_trace_printk).  This is the simplest
 * end-to-end libbpf example: it shows the skeleton open/load/attach cycle and
 * the classic trace_pipe debugging path.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
	/* The format string must live on the stack as a separate char array for
	 * the verifier to accept it with bpf_trace_printk. */
	char fmt[] = "Hello eBPF! pid=%d comm=%s\n";
	char comm[16] = {};
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_trace_printk(fmt, sizeof(fmt), pid, comm);
	return 0;
}
