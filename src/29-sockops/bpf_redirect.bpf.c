// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 29-sockops: sk_msg redirect — bypass the TCP/IP stack for local traffic.
 *
 * When a process sends data on a local (127.0.0.1) TCP connection, this
 * program looks up the receiving socket in the sockhash and, if found,
 * redirects the message directly to the receiver's ingress queue (bypassing
 * the TCP/IP stack).  If the target socket is not in the map (e.g. connection
 * not yet tracked), the message falls through to the normal TCP path.
 */
#include "bpf_sockmap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
	if (msg->remote_ip4 != LOCALHOST_IPV4 ||
	    msg->local_ip4 != LOCALHOST_IPV4)
		return SK_PASS;

	struct sock_key key = {
		.sip = msg->remote_ip4,
		.dip = msg->local_ip4,
		.dport = bpf_htonl(msg->local_port),
		.sport = msg->remote_port,
		.family = msg->family,
	};

	/* bpf_msg_redirect_hash returns SK_PASS on success (message redirected),
	 * SK_DROP on failure (key not found).  Returning SK_DROP would cause
	 * EPERM on send().  Instead, always return SK_PASS so that a failed
	 * redirect falls through to the normal TCP send path. */
	bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
	return SK_PASS;
}
