// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 72-ksyscall: 跨架构系统调用追踪 — ksyscall + kretsyscall。
 *
 * SEC("ksyscall/openat")    — 入口探针，获取 openat 参数（dfd, filename, flags）
 * SEC("kretsyscall/openat") — 返回探针，获取 openat 返回值（fd 或错误码）
 *
 * ksyscall 的核心价值：跨架构兼容。
 *   kprobe/__arm64_sys_openat  → 只在 aarch64 工作
 *   kprobe/__x64_sys_openat    → 只在 x86_64 工作
 *   ksyscall/openat            → libbpf 自动解析为正确架构的函数名
 *
 * 注意：ksyscall 挂载到 __arm64_sys_openat，该函数接收 struct pt_regs* 参数。
 * 实际的系统调用参数在 pt_regs 内部，需要通过 PT_REGS_PARM 提取：
 *   PT_REGS_PARM1(ctx) = struct pt_regs*（系统调用的寄存器上下文）
 *   从中提取：dfd=PARM1(sc_regs), filename=PARM2(sc_regs), flags=PARM3(sc_regs)
 *
 * 通过 HASH map（key=pid）在入口和返回之间传递时间戳，计算 syscall 延迟。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ksyscall.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct entry_data {
	__u64 ts_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct entry_data);
} entry_map SEC(".maps");

const volatile __u32 target_pid = 0;

/* ① 入口探针：ksyscall/openat
 *
 * __arm64_sys_openat(struct pt_regs *regs) 接收一个 pt_regs 指针，
 * 实际的 syscall 参数在 pt_regs 内部。 */
SEC("ksyscall/openat")
int BPF_KPROBE(handle_enter)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct pt_regs *sc_regs;
	int dfd, flags;
	const char *filename;
	struct event *e;
	struct entry_data data = {};

	if (target_pid && target_pid != pid)
		return 0;

	/* 从 kprobe 上下文中提取系统调用参数。
	 * __arm64_sys_openat 接收 struct pt_regs*，实际 syscall 参数在内层 pt_regs 中。
	 * 使用 BPF_CORE_READ 安全读取内核内存。 */
	sc_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	dfd = (int)BPF_CORE_READ(sc_regs, regs[0]);
	filename = (const char *)BPF_CORE_READ(sc_regs, regs[1]);
	flags = (int)BPF_CORE_READ(sc_regs, regs[2]);

	/* 记录入口时间戳到 HASH map */
	data.ts_ns = bpf_ktime_get_ns();
	bpf_map_update_elem(&entry_map, &pid, &data, BPF_ANY);

	/* 发送 ENTRY 事件 */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_ENTRY;
	e->pid = pid;
	e->ts_ns = data.ts_ns;
	e->flags = flags;
	e->ret = 0;
	e->latency_ns = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ② 返回探针：kretsyscall/openat
 *
 * ret = openat 的返回值（fd 或负错误码） */
SEC("kretsyscall/openat")
int BPF_KRETPROBE(handle_exit, int ret)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct entry_data *data;
	struct event *e;
	__u64 now, latency;

	if (target_pid && target_pid != pid)
		return 0;

	/* 从 HASH map 取入口时间戳 */
	data = bpf_map_lookup_elem(&entry_map, &pid);
	if (!data)
		return 0;

	now = bpf_ktime_get_ns();
	latency = now - data->ts_ns;

	bpf_map_delete_elem(&entry_map, &pid);

	/* 发送 EXIT 事件 */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_EXIT;
	e->pid = pid;
	e->ret = ret;
	e->ts_ns = now;
	e->latency_ns = latency;
	e->flags = 0;
	e->filename[0] = '\0';
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
