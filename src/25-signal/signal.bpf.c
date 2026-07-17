// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 25-signal: detect a target command and terminate it with bpf_send_signal.
 *
 * On sys_enter_execve, check the comm/argv against a target string; if matched,
 * call bpf_send_signal(SIGKILL) to kill the process before it runs.
 * Teaches: bpf_send_signal (kernel→userspace signal injection), execve args.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int target_strlen = 0;
const char target_name[16] = {};

SEC("tp/syscalls/sys_enter_execve")
int handle_exec(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[0];
	char comm[16] = {};

	if (target_strlen <= 0 || target_strlen > 16)
		return 0;

	/* Read the basename of the executable path. */
	bpf_probe_read_user_str(comm, sizeof(comm), filename);
	char tmp[16];
	bpf_probe_read_kernel(tmp, target_strlen, target_name);

	/* Check if the filename contains the target (simple suffix match). */
	int i, j, len = 0;
	while (comm[len] && len < 16) len++;
	bool match = false;
	for (i = 0; i + target_strlen <= len; i++) {
		bool m = true;
		for (j = 0; j < target_strlen; j++)
			if (comm[i + j] != tmp[j]) { m = false; break; }
		if (m) { match = true; break; }
	}

	if (match)
		bpf_send_signal(9 /* SIGKILL */);

	return 0;
}
