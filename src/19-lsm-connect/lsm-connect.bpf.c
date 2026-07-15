// SPDX-License-Identifier: GPL-2.0
/* 19-lsm-connect: block connect() to a fixed IP via BPF LSM.
 *
 * Kernel side: a BPF LSM program on the socket_connect hook that denies
 * connects to 1.1.1.1 (16843009 in network-byte-order int).  Demonstrates the
 * "cannot override a denial" LSM rule and function-level security checks.
 *
 * NOTE: requires the kernel to be booted with `bpf` in the active LSM list
 * (see README.md).  On hosts where bpf is not an active LSM, attach will fail
 * (the program still compiles and loads).
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

const volatile __u32 blockme = 16843009; /* 1.1.1.1 as a big-endian u32 */

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	/* Cannot override a previous denial. */
	if (ret != 0)
		return ret;

	if (address->sa_family != AF_INET)
		return 0;

	struct sockaddr_in *addr = (struct sockaddr_in *)address;
	__u32 dest = addr->sin_addr.s_addr;

	bpf_printk("lsm: found connect to %u", dest);

	if (dest == blockme) {
		bpf_printk("lsm: blocking %u", dest);
		return -EPERM;
	}
	return 0;
}
