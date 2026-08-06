// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 73-lsm-cgroup: BPF 内核态 — cgroup 级 LSM 安全策略。
 *
 * SEC("lsm_cgroup/socket_connect") 挂载到 socket_connect LSM 钩子，
 * 但作用范围限制在 attach 的 cgroup 内（不影响系统其他进程）。
 *
 * 策略：阻止 cgroup 内进程 connect 到 127.0.0.1:9999。
 *
 * 与 19-lsm-connect（lsm/mac）的关键区别：
 *   - lsm/mac: 全局生效，返回 -EPERM 拒绝
 *   - lsm_cgroup: cgroup 级生效，返回 0 拒绝，1 允许（与 lsm/mac 相反！）
 *   - lsm_cgroup 需要 bpf_program__attach_cgroup 手动挂载到 cgroup
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "lsm-cg.h"

#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2

SEC("lsm_cgroup/socket_connect")
int BPF_PROG(block_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	/* 不覆盖既有拒绝 */
	if (ret != 0)
		return 1;  /* 已有拒绝，放行让后续 hook 处理 */

	__u16 family;
	bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

	if (family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *)address;
		__be32 dest;
		__be16 dport;

		bpf_probe_read_kernel(&dest, sizeof(dest), &addr->sin_addr.s_addr);
		bpf_probe_read_kernel(&dport, sizeof(dport), &addr->sin_port);

		if (dest == BLOCK_IP && dport == bpf_htons(BLOCK_PORT)) {
			__u32 pid = bpf_get_current_pid_tgid() >> 32;
			bpf_printk("lsm_cgroup: pid=%d blocked 127.0.0.1:%d", pid, BLOCK_PORT);
			return 0;  /* deny: 0 = stop, deny */
		}
	}

	return 1;  /* allow: 1 = continue, allow */
}

