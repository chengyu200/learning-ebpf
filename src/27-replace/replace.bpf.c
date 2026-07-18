// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 27-replace: transparently replace text in file reads.
 *
 * On sys_exit_read, scan the returned buffer and replace every occurrence of a
 * configured "from" string with a "to" string (same length) using
 * bpf_probe_write_user.  Demonstrates in-place modification of userspace data
 * returned by the kernel.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int from_len = 0;
const volatile int to_len = 0;
const volatile char from_str[16] = {};
const volatile char to_str[16] = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, void *);
} buf_map SEC(".maps");

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	void *buf = (void *)ctx->args[1];
	bpf_map_update_elem(&buf_map, &pid, &buf, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	void **bufp, *buf;
	int ret = (int)ctx->ret;
	char data[128];
	int i, j, len;

	if (ret <= 0)
		goto out;
	bufp = bpf_map_lookup_elem(&buf_map, &pid);
	if (!bufp)
		return 0;
	buf = *bufp;

	if (from_len <= 0 || from_len > 16 || to_len != from_len)
		goto out;

	len = ret > (int)sizeof(data) ? (int)sizeof(data) : ret;
	if (bpf_probe_read_user(data, len, buf))
		goto out;

	for (i = 0; i + from_len <= len; i++) {
		bool match = true;
		for (j = 0; j < from_len; j++)
			if (data[i + j] != from_str[j]) { match = false; break; }
		if (match) {
			if (bpf_probe_write_user(buf + i, to_str, to_len))
				bpf_printk("replace: write failed at offset %d", i);
			else
				bpf_printk("replace: replaced at offset %d", i);
			i += from_len - 1;
		}
	}

out:
	bpf_map_delete_elem(&buf_map, &pid);
	return 0;
}
