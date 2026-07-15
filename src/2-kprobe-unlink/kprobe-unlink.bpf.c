// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 2-kprobe-unlink: monitor file deletion via kprobe.
 *
 * Kernel side: attach a kprobe to vfs_unlink() and send the filename being
 * removed, together with pid/uid/comm, to user space through a ring buffer.
 * (The original bpf-developer-tutorial hooks do_unlinkat; this kernel no
 * longer exports do_unlinkat, so we use the stable vfs_unlink entry point and
 * read the name from the target dentry.)
 * Teaches: kprobe attachment, BPF_KPROBE macro, reading nested kernel struct
 * fields with BPF_CORE_READ (dentry->d_name.name), ring buffer output.
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

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(handle_vfs_unlink, struct mnt_idmap *idmap,
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
