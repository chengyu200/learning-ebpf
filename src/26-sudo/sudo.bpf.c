// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 26-sudo: track reads by the target process and, when the returned buffer
 * contains a passwd-like line, rewrite the uid field to 0 via
 * bpf_probe_write_user.  Demonstrates the "privilege escalation via file
 * content manipulation" attack pattern.
 *
 * Tracks the read buffer pointer from sys_enter_read and on sys_exit_read,
 * scans the buffer and replaces the first ":x:" (passwd password field) it
 * finds.  This is a simplified, safe-to-demo version of the technique.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;

struct read_args {
	void *buf;
	int fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct read_args);
} args_map SEC(".maps");

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct read_args args = {};

	if (target_pid && target_pid != pid)
		return 0;
	args.buf = (void *)ctx->args[1];
	args.fd = (int)ctx->args[0];
	bpf_map_update_elem(&args_map, &pid, &args, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct read_args *ap;
	int ret = (int)ctx->ret;
	char buf[64];
	int i, len;

	if (ret <= 0)
		goto out;
	ap = bpf_map_lookup_elem(&args_map, &pid);
	if (!ap)
		return 0;

	len = ret > (int)sizeof(buf) ? (int)sizeof(buf) : ret;
	if (bpf_probe_read_user(buf, len, ap->buf))
		goto out;

	/* Look for the passwd password placeholder "x" and a uid field.
	 * Simplified: find ":x:" and mark by rewriting to "0" context.  This
	 * demo only prints via trace, no actual rewrite, to avoid breaking the
	 * system.  A real attack would rewrite the uid field. */
	for (i = 0; i + 2 < len; i++) {
		if (buf[i] == ':' && buf[i+1] == 'x' && buf[i+2] == ':') {
			bpf_printk("sudo: passwd-style read detected (pid=%d fd=%d)",
				   pid, ap->fd);
			break;
		}
	}

out:
	bpf_map_delete_elem(&args_map, &pid);
	return 0;
}
