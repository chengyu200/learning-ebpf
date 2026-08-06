// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 70-fexit-unlink: 用 fexit 追踪文件删除结果（成功/失败）。
 *
 * 两个 fexit 程序配合：
 *
 * ① fexit/vfs_unlink
 *    - 在 VFS 层退出时触发，能读取文件名（dentry->d_name.name）
 *    - 能捕获路径查找成功后的删除结果（权限失败、只读 FS 等）
 *    - 无法捕获 ENOENT（文件不存在），因为 vfs_unlink 不会被调用
 *
 * ② fexit/__arm64_sys_unlinkat
 *    - 在系统调用退出时触发，捕获所有 unlinkat 的返回值
 *    - 能捕获 ENOENT（文件不存在），因为错误在 do_unlinkat 中返回
 *    - 无法直接读取文件名（参数是 pt_regs*，需从用户态内存读取）
 *
 * 两者配合：sys_unlinkat 捕获所有结果（含 ENOENT），
 *          vfs_unlink 提供文件名详情。
 *
 * fexit vs fentry 的核心区别：
 *   fentry 只知道"谁要删什么文件"（入口参数），不知道是否删除成功
 *   fexit  知道"谁删了什么文件，成功还是失败"（入口参数 + 返回值）
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fexit-unlink.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ① fexit/vfs_unlink：有文件名，能捕获权限失败等 */
SEC("fexit/vfs_unlink")
int BPF_PROG(handle_vfs_unlink, struct mnt_idmap *idmap,
	     struct inode *dir, struct dentry *dentry,
	     struct inode **delegated, int ret)
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
	e->ret = ret;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	path = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), path);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ② fexit/__arm64_sys_unlinkat：捕获所有结果（含 ENOENT）
 *
 * __arm64_sys_unlinkat 是系统调用入口，接收 pt_regs*。
 * do_unlinkat 被内联到这个函数中，所以 fexit 能捕获
 * 路径查找失败（ENOENT）的返回值。
 *
 * 文件名无法从 pt_regs 直接读取（需要从用户态内存 copy），
 * 这里只记录返回值，文件名留空。 */
SEC("fexit/__arm64_sys_unlinkat")
int BPF_PROG(handle_sys_unlinkat, struct pt_regs *regs, long ret)
{
	struct event *e;
	pid_t pid;

	/* 只记录失败的 unlinkat（成功的已被 vfs_unlink 记录） */
	if (ret == 0)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	e->uid = bpf_get_current_uid_gid();
	e->ret = (int)ret;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	/* 文件名无法从 pt_regs 直接获取，标记为 "(unknown)" */
	__builtin_memcpy(e->filename, "(unknown)", 10);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
