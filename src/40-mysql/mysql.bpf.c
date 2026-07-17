// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 40-mysql: trace SQL query dispatch via uprobe on dispatch_command.
 *
 * MariaDB/MySQL dispatch_command signature:
 *   dispatch_command(enum_server_command command, THD *thd,
 *                    char *packet, unsigned int packet_length, bool)
 *
 * For COM_QUERY, the packet starts with a 1-byte command code followed by the
 * query text.  We read packet+1 as the query string.
 *
 * NOTE: MariaDB is C++ so the symbol is mangled.  The user-space loader uses
 * nm to find the mangled name automatically, or falls back to offset.
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
	char query[MAX_QUERY];
};

/* dispatch_command(command, thd, packet, packet_length, ...)
 * arg2 = char *packet (the raw command packet)
 * arg3 = unsigned int packet_length
 */
SEC("uprobe")
int BPF_KPROBE(mysql_dispatch, int command, void *thd,
	       const char *packet, unsigned int packet_length)
{
	struct event *e;

	/* COM_QUERY = 3, COM_STMT_PREPARE = 22 */
	if (command != 3 && command != 22)
		return 0;
	if (packet_length <= 1)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ts_ns = bpf_ktime_get_ns();

	unsigned int qlen = packet_length - 1;
	if (qlen >= MAX_QUERY)
		qlen = MAX_QUERY - 1;
	bpf_probe_read_user_str(&e->query, MAX_QUERY, packet);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
