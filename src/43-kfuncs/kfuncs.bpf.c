// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 43-kfuncs: BPF program that calls a custom kfunc registered by the
 * bpf_kfunc_demo kernel module.  The kfunc `bpf_kfunc_greet` is declared as
 * an extern here; the verifier resolves it against the module's BTF at load
 * time.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* extern kfunc — resolved via BTF (kernel or module). */
extern const char *bpf_kfunc_greet(void) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct event {
	__u32 pid;
	char msg[64];
};

SEC("tp/syscalls/sys_enter_execve")
int call_kfunc(void *ctx)
{
	struct event *e;
	const char *greet;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;

	greet = bpf_kfunc_greet();
	/* kfunc 返回 const char* 指向一个字符串常量。
	 * verifier 知道返回值的内存大小为 1 字节（const char），
	 * 不能直接用 greet[i] 做数组下标访问（越界检查会失败）。
	 * 用 bpf_probe_read_kernel_str 安全地读取整个字符串。 */
	bpf_probe_read_kernel_str(e->msg, sizeof(e->msg), greet);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
