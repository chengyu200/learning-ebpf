// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 67-fmod-ret: 内核态 BPF 程序 — 用 BPF_MODIFY_RETURN 注入错误。
 *
 * 挂载到 __arm64_sys_read（read 系统调用入口），根据用户态配置
 * 向目标进程注入错误返回值（如 -ENOMEM），跳过原始 read() 执行。
 *
 * 教学概念：
 * - BPF_MODIFY_RETURN：tracing 程序的 attach 类型，可决定是否执行原始函数
 * - SEC("fmod_ret/function")：libbpf 自动解析为 modify_return trampoline
 * - 返回值语义：返回 0 = 放行；返回非0 = 跳过原始函数，返回值=注入值
 * - ALLOW_ERROR_INJECTION：只有标记了此属性的内核函数才能用 fmod_ret
 *
 * Trampoline 执行顺序：
 *   fentry（观察）→ fmod_ret（修改）→ 原始函数 → fexit（观察）
 *                              ↑
 *                    返回 0：执行原始函数
 *                    返回非0：跳过原始函数
 *
 * 与 lesson 34-syscall（bpf_override_return）对比：
 *   34 用 kprobe + bpf_override_return（int3 断点，需 CONFIG_BPF_KPROBE_OVERRIDE）
 *   67 用 fmod_ret（trampoline，需 CONFIG_FUNCTION_ERROR_INJECTION）
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fmod-ret.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * 用户态配置（在 load 前通过 rodata 设置）：
 *   target_pid: 目标进程 PID（0 = 所有进程）
 *   inject_errno: 要注入的错误码（如 -ENOMEM=-12, -EPERM=-1）
 *                0 = 不注入（正常放行）
 */
const volatile pid_t target_pid = 0;
const volatile int inject_errno = 0;

/*
 * fmod_ret 程序：在 __arm64_sys_read 执行之前调用。
 *
 * @regs  原始函数的参数（struct pt_regs *）
 * @return 0 = 放行（read 正常执行）
 *         非0 = 跳过 read，返回值=错误码
 */
SEC("fmod_ret/__arm64_sys_read")
int BPF_PROG(inject_read_error, struct pt_regs *regs)
{
	u32 pid;

	/* 如果未设置注入错误码，放行 */
	if (inject_errno == 0)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* 如果指定了目标 PID 且不匹配，放行 */
	if (target_pid && target_pid != pid)
		return 0;

	/* 注入错误：返回非0值跳过原始 read() */
	char comm[TASK_COMM_LEN] = {};
	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("fmod_ret: inject errno %d to pid %d (%s)",
		   inject_errno, pid, comm);

	return inject_errno;
}
