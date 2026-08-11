// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 81-sk-skb: SK_SKB stream parser + verdict.
 *
 * Program type: BPF_PROG_TYPE_SK_SKB
 * Context:     struct __sk_buff (same as TC programs, but with
 *              family/local_ip/remote_ip/local_port/remote_port fields)
 *
 * Three SEC names (4th "sk_skb/verdict" is newer, documented in README):
 *   1. SEC("sk_skb/stream_parser") — parse TCP stream into messages
 *   2. SEC("sk_skb/stream_verdict") — verdict on each parsed message
 *   3. SEC("sk_skb") (bare) — legacy/generic form, attach_type=0
 *
 * Message protocol: [4-byte BE length] [payload]
 *   e.g. \x00\x00\x00\x05Hello  (total 9 bytes)
 *
 * stream_parser logic:
 *   - bpf_skb_pull_data to ensure 4-byte header is accessible
 *   - read 4-byte BE payload length from packet data
 *   - return 4 + payload_len if full message available, 0 if need more data
 *
 * stream_verdict logic:
 *   - log message info (size, ports, family) to ringbuf
 *   - return SK_PASS to deliver to userspace
 *
 * Return values (enum sk_action):
 *   SK_PASS = 1 (deliver/redirect)
 *   SK_DROP = 0 (drop)
 *
 * Attach: bpf_program__attach_sockmap(prog, sockmap_fd)
 *   Both programs attach to the same BPF_MAP_TYPE_SOCKMAP.
 *   Sockets must be added to the map via bpf_map_update_elem from userspace.
 *
 * Comparison with 29-sockops (sk_msg):
 *   sk_skb = receive path (stream_parser + stream_verdict on incoming data)
 *   sk_msg = send path (verdict on tcp_sendmsg outgoing data)
 *   Together they form the "sockmap three-piece set" with sockops.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "sk_skb.h"

char LICENSE[] SEC("license") = "GPL";

/* SOCKMAP: stores socket references. Both programs attach to this map.
 * Key = __u32 (index), Value = int (socket fd from userspace).
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u32);
} sockmap SEC(".maps");

/* Ringbuf: event channel to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

#define HEADER_LEN 4

/* 1. stream_parser — parse TCP stream into length-prefixed messages.
 *
 * Return value: number of bytes belonging to this message (>= HEADER_LEN),
 * or 0 if more data is needed.
 *
 * The kernel calls this program whenever new data arrives on a socket
 * that is in the SOCKMAP. If it returns N, the kernel delivers the first
 * N bytes to stream_verdict as a single message, then re-invokes
 * stream_parser on the remaining data.
 */
SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb)
{
	__u32 data_len = skb->len;

	/* Need at least 4 bytes for the length header */
	if (data_len < HEADER_LEN)
		return 0;

	/* Ensure header data is accessible in skb linear area */
	if (bpf_skb_pull_data(skb, HEADER_LEN) < 0)
		return 0;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data + HEADER_LEN > data_end)
		return 0;

	/* Read 4-byte big-endian payload length */
	__u32 payload_len = bpf_ntohl(*(__u32 *)data);

	/* Sanity check: payload_len must be reasonable */
	if (payload_len == 0 || payload_len > 65536)
		return data_len;  /* pass through as-is on invalid header */

	__u32 total = HEADER_LEN + payload_len;

	/* If we don't have the full message yet, wait for more data */
	if (data_len < total)
		return 0;

	/* Return total message size — kernel delivers exactly this many bytes
	 * to stream_verdict, then re-invokes us on the remainder. */
	return total;
}

/* 2. stream_verdict — verdict on each parsed message.
 *
 * Called after stream_parser returns N. The skb contains exactly N bytes
 * (one complete message). We log the message info and return SK_PASS
 * to deliver it to userspace recv().
 *
 * Could also use bpf_sk_redirect_map() to forward to another socket
 * in the SOCKMAP (demonstrated in README).
 */
SEC("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff *skb)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->msg_size    = skb->len;
		e->family      = skb->family;
		e->local_port  = skb->local_port;   /* host byte order */
		e->remote_port = skb->remote_port;  /* network byte order */
		e->pid         = bpf_get_current_pid_tgid() >> 32;
		e->ts_ns       = bpf_ktime_get_ns();
		bpf_get_current_comm(&e->comm, sizeof(e->comm));

		/* Read payload length from the header for logging */
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;
		if (data + HEADER_LEN <= data_end)
			e->payload_len = bpf_ntohl(*(__u32 *)data);
		else
			e->payload_len = 0;

		bpf_ringbuf_submit(e, 0);
	}

	return SK_PASS;
}

/*
 * 3. SEC("sk_skb") (bare) — legacy/generic form.
 *    attach_type = 0 (SEC_NONE), not attachable via bpf_program__attach_sockmap.
 *    Kept as comment for documentation; not used in this example.
 *
 * 4. SEC("sk_skb/verdict") — newer verdict-only attach point
 *    (BPF_SK_SKB_VERDICT, added in kernel 5.12).
 *    Does not require stream_parser; works on individual skbs.
 *    Not used here to keep the example focused on the parser+verdict pair.
 */
