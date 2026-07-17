// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 30-sslsniff: capture plaintext SSL/TLS data via uprobe on SSL_read/SSL_write.
 *
 * SSL_read(const SSL *ssl, void *buf, int num) -> ret = bytes read.
 * SSL_write(const SSL *ssl, const void *buf, int num) -> ret = bytes written.
 * We use uretprobe on SSL_read (buf filled on return) and uprobe on SSL_write
 * (buf valid on entry).  Teaches uprobe on shared libraries.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sslsniff.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} rb SEC(".maps");

/* On SSL_write entry: buf (arg2) is valid and num (arg3) is the length. */
SEC("uprobe")
int BPF_KPROBE(ssl_write_entry, const void *ssl, const void *buf, int num)
{
	struct event *e;
	int len = num;

	if (len <= 0)
		return 0;
	if (len > MAX_DATA_SIZE)
		len = MAX_DATA_SIZE;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ts_ns = bpf_ktime_get_ns();
	e->rw = 1;
	e->data_len = len;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user(&e->data, len, buf);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* On SSL_read return: ret is bytes read; the buf (arg1) was filled by the call.
 * We saved buf in a hash on entry; here we read it.  Simplified: use uretprobe
 * and re-read arg1 from the saved ctx via a per-pid stash. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, const void *);
} read_bufs SEC(".maps");

SEC("uprobe")
int BPF_KPROBE(ssl_read_entry, const void *ssl, void *buf, int num)
{
	u32 pid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&read_bufs, &pid, &buf, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(ssl_read_ret)
{
	u32 pid = bpf_get_current_pid_tgid();
	const void **bufp;
	const void *buf;
	int ret = (int)PT_REGS_RC(ctx);
	struct event *e;
	int len;

	if (ret <= 0)
		goto out;
	len = ret > MAX_DATA_SIZE ? MAX_DATA_SIZE : ret;

	bufp = bpf_map_lookup_elem(&read_bufs, &pid);
	if (!bufp)
		goto out;
	buf = *bufp;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->pid = pid;
		e->ts_ns = bpf_ktime_get_ns();
		e->rw = 0;
		e->data_len = len;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_probe_read_user(&e->data, len, buf);
		bpf_ringbuf_submit(e, 0);
	}

out:
	bpf_map_delete_elem(&read_bufs, &pid);
	return 0;
}
