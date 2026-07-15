// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 6-sigsnoop: capture signal sending (kill/tkill/tgkill) with hash-map state.
 *
 * Kernel side: on sys_enter_{kill,tkill,tgkill} store the target pid and signal
 * number in a hash map keyed by the sender's pid_tgid; on sys_exit_* look it up,
 * emit {sender pid, target pid, signal, return value} to a ring buffer, then
 * delete the entry.  An optional global variable filters by signal number.
 * Teaches: hash maps to carry state across enter/exit, multiple tracepoints,
 * ring buffer output.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sigsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int target_sig = 0;

struct sig_val {
	int tpid;
	int sig;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);            /* pid_tgid */
	__type(value, struct sig_val);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline int enter_sig(u64 id, int tpid, int sig)
{
	struct sig_val v = {};

	if (target_sig && target_sig != sig)
		return 0;
	v.tpid = tpid;
	v.sig = sig;
	bpf_map_update_elem(&start, &id, &v, BPF_ANY);
	return 0;
}

/* kill(pid_t pid, int sig) -> args[0]=pid, args[1]=sig */
SEC("tp/syscalls/sys_enter_kill")
int sig_enter_kill(struct trace_event_raw_sys_enter *ctx)
{
	return enter_sig(bpf_get_current_pid_tgid(),
			(int)ctx->args[0], (int)ctx->args[1]);
}

/* tkill(pid_t tid, int sig) -> args[0]=tid, args[1]=sig */
SEC("tp/syscalls/sys_enter_tkill")
int sig_enter_tkill(struct trace_event_raw_sys_enter *ctx)
{
	return enter_sig(bpf_get_current_pid_tgid(),
			(int)ctx->args[0], (int)ctx->args[1]);
}

/* tgkill(pid_t tgid, pid_t tid, int sig) -> args[0]=tgid, args[1]=tid, args[2]=sig */
SEC("tp/syscalls/sys_enter_tgkill")
int sig_enter_tgkill(struct trace_event_raw_sys_enter *ctx)
{
	return enter_sig(bpf_get_current_pid_tgid(),
			(int)ctx->args[1], (int)ctx->args[2]);
}

static __always_inline int exit_sig(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	int ret = (int)ctx->ret;
	struct sig_val *vp;
	struct event *e;

	vp = bpf_map_lookup_elem(&start, &id);
	if (!vp)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		goto out;

	e->pid = pid;
	e->tpid = vp->tpid;
	e->sig = vp->sig;
	e->ret = ret;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);

out:
	bpf_map_delete_elem(&start, &id);
	return 0;
}

SEC("tp/syscalls/sys_exit_kill")
int sig_exit_kill(struct trace_event_raw_sys_exit *ctx)    { return exit_sig(ctx); }
SEC("tp/syscalls/sys_exit_tkill")
int sig_exit_tkill(struct trace_event_raw_sys_exit *ctx)  { return exit_sig(ctx); }
SEC("tp/syscalls/sys_exit_tgkill")
int sig_exit_tgkill(struct trace_event_raw_sys_exit *ctx) { return exit_sig(ctx); }
