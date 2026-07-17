// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 34-syscall: inspect and demonstrate modifying syscall arguments.
 *
 * Hooks sys_enter_openat via tracepoint, reads the filename + flags, and logs.
 * Demonstrates syscall argument access.  Full argument modification (redirect
 * the open to a different path) requires bpf_override + CONFIG_BPF_KPROBE_OVERRIDE
 * on a kprobe of the arch-specific syscall handler (__arm64_sys_openat here).
 *
 * NOTE: requires CONFIG_BPF_KPROBE_OVERRIDE=y (confirmed on this kernel).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

const volatile pid_t target_pid = 0;
const volatile bool do_override = false;

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	const char *filename = (const char *)ctx->args[1];
	int flags = (int)ctx->args[2];
	char path[64];

	if (target_pid && target_pid != pid)
		return 0;

	bpf_probe_read_user_str(path, sizeof(path), filename);
	bpf_printk("syscall: pid=%d openat(\"%s\", flags=0x%x)", pid, path, flags);

	return 0;
}

/* Override variant: a kprobe on the arch syscall handler.  On aarch64 the
 * entry is __arm64_sys_openat.  bpf_override is only supported when
 * CONFIG_BPF_KPROBE_OVERRIDE=y. */
SEC("kprobe/__arm64_sys_openat")
int BPF_KPROBE(override_openat)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid && target_pid != pid)
		return 0;
	/* bpf_override_return would deny the syscall; commented out to
	 * avoid breaking openat system-wide.  Uncomment to test on a targeted pid. */
	if (do_override)
		return bpf_override_return(ctx, -1); /* -EPERM */
	return 0;
}
