// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 69-freplace: 扩展 BPF 程序 — 替换 target 的 filter_check()。
 *
 * SEC("freplace/filter_check") 声明替换 target 程序中的 filter_check 函数。
 * 用户态加载时需设置 attach_prog_fd = target 的 prog fd。
 *
 * 替换后效果：filter_check 只对 PID为偶数的进程 返回 true。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* 替换 filter_check：只记录 PID 为偶数的进程
 * 注意：函数名必须与 target 中的被替换函数同名 */
SEC("freplace/filter_check")
int filter_check(__u32 pid)
{
	return (pid % 2) == 0 ? 1 : 0;
}
