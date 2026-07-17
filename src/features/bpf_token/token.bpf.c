// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* features/bpf_token: delegated privilege via BPF token.
 *
 * Creates a bpf_token from a bpffs mount (with delegation options) and shows
 * that a BPF program can be loaded using the token with reduced capabilities.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_execve")
int token_demo(void *ctx)
{
	return 0;
}
