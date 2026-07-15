// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 3-fentry-unlink: monitor file deletion via fentry (BTF-based).
 *
 * Kernel side: same goal as 2-kprobe-unlink, but uses an fentry hook on
 * vfs_unlink().  fentry is BTF-based (no kprobe arg extraction), gives typed
 * arguments directly, and has lower overhead than kprobe.
 * (do_unlinkat is not exported on this kernel, so vfs_unlink is used instead.)
 * Teaches: fentry/fexit attachment, BPF_PROG macro, contrast with kprobe.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "unlink.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("fentry/vfs_unlink")
int BPF_PROG(handle_vfs_unlink, struct mnt_idmap *idmap,
	     struct inode *dir, struct dentry *dentry,
	     struct inode **delegated)
{
	struct event *e;
	pid_t pid;
	u32 uid;
	const char *path;

	pid = bpf_get_current_pid_tgid() >> 32;
	uid = bpf_get_current_uid_gid();

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	e->uid = uid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	/* Read the file name from the target dentry: dentry->d_name.name */
	path = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), path);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
