// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 40-mysql: trace MySQL query dispatch via uprobe on dispatch_command.
 *
 * In MySQL/mysqld, dispatch_command is the entry point for processing a
 * COM_QUERY.  This BPF program captures the query string (arg at offset 1,
 * depending on MySQL version) and sends it to user space.
 *
 * NOTE: compile-only on hosts without mysqld.  Requires a running mysqld with
 * the dispatch_command symbol (built with debug info) to attach.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_QUERY 256

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct event {
	__u32 pid;
	__u64 ts_ns;
	__u16 query_len;
	char query[MAX_QUERY];
};

/* dispatch_command(COM_DATA *com_data, ...) — the query text lives in
 * com_data->query (aLEX_STRING).  This is version-dependent; for simplicity
 * we capture arg1 (com_data) and read the first field as a char*.
 * Adjust the offset for your MySQL build if needed. */
SEC("uprobe")
int BPF_KPROBE(mysql_dispatch, const void *com_data)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ts_ns = bpf_ktime_get_ns();

	/* com_data->query is typically { const char *str; size_t length; }
	 * at offset 0 of COM_DATA for COM_QUERY.  Read the pointer directly. */
	const char *query = NULL;
	bpf_probe_read_user(&query, sizeof(query), com_data);
	bpf_probe_read_user_str(&e->query, MAX_QUERY, query);
	e->query_len = 0; /* filled by user space via strnlen */

	bpf_ringbuf_submit(e, 0);
	return 0;
}
