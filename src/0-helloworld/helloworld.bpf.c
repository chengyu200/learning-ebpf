// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_execve")
int bpf_prog(void *ctx)
{
	char msg[] = "Hello, BPF World!";
	bpf_trace_printk(msg, sizeof(msg));

	return 0;
}
