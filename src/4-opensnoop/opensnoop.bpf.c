// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 4-opensnoop: trace openat() syscalls with global-variable filtering.
 *
 * Kernel side: hook sys_enter_openat to capture the filename and sys_exit_openat
 * to capture the return value (fd / -errno).  A hash map keyed by pid_tgid
 * carries the filename from enter to exit.  Global const variables (set from
 * user space before load) filter by PID and by success/failure.
 * Teaches: global variables as BPF configuration, enter/exit matching with a
 * hash map, bpf_probe_read_user_str, ring buffer output.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "opensnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;
const volatile bool failed_only = false;

struct fname_val {
	char filename[MAX_FILENAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);            /* pid_tgid */
	__type(value, struct fname_val);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	struct fname_val val = {};
	const char *filename_ptr;

	if (target_pid && target_pid != pid)
		return 0;

	filename_ptr = (const char *)ctx->args[1];
	bpf_probe_read_user_str(val.filename, sizeof(val.filename), filename_ptr);
	bpf_map_update_elem(&start, &id, &val, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	int ret = (int)ctx->ret;
	struct fname_val *valp;
	struct event *e;

	if (target_pid && target_pid != pid)
		return 0;
	if (failed_only && ret >= 0)
		return 0;

	valp = bpf_map_lookup_elem(&start, &id);
	if (!valp)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		goto out;

	e->pid = pid;
	e->uid = bpf_get_current_uid_gid();
	e->ret = ret;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), valp->filename);
	bpf_ringbuf_submit(e, 0);

out:
	bpf_map_delete_elem(&start, &id);
	return 0;
}
