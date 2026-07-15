/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2020 Wenbo Zhang */
#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

#define TASK_COMM_LEN 16

struct event {
	__u32 saddr_v4;
	__u32 daddr_v4;
	__u32 saddr_v6[4];
	__u32 daddr_v6[4];
	__u64 ts_us;
	__u64 delta_us;
	__u32 pid;
	__u32 tgid;
	__u16 lport;
	__u16 dport;
	__u8 af;
	char comm[TASK_COMM_LEN];
};

#endif
