/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Based on agentsight/bpf/sslsniff.h — simplified, OpenSSL only. */
#ifndef __SSLSNIFF_H
#define __SSLSNIFF_H

#define MAX_BUF_SIZE      (512 * 1024)      /* per-event payload capture limit */
#define RING_BUFFER_SIZE  (4 * 1024 * 1024)
#define TASK_COMM_LEN     16

struct probe_SSL_data_t {
	__u64 timestamp_ns;
	__u64 delta_ns;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 len;               /* actual bytes read/written */
	__u32 buf_size;         /* bytes copied into buf */
	int buf_filled;
	int rw;                  /* 0=read, 1=write, 2=handshake */
	char comm[TASK_COMM_LEN];
	char buf[MAX_BUF_SIZE];
	int is_handshake;
};

#endif /* __SSLSNIFF_H */
