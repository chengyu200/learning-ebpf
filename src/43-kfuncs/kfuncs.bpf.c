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
	int i = 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;

	greet = bpf_kfunc_greet();
	/* Copy up to 63 bytes of the returned string. */
	while (i < 63 && greet[i]) {
		e->msg[i] = greet[i];
		i++;
	}
	e->msg[i] = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
