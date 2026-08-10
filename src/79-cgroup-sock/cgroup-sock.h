/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 79-cgroup-sock: Socket lifecycle auditor shared definitions.
 */
#ifndef __CGROUP_SOCK_H
#define __CGROUP_SOCK_H

#define TASK_COMM_LEN 16

/* Socket family/type constants.
 * These are needed by BPF programs (no system headers available).
 * Guard with #ifndef to avoid conflicts with system headers in userspace. */
#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6  10
#endif

#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM  2
#endif
#ifndef SOCK_RAW
#define SOCK_RAW    3
#endif

/* IPPROTO_RAW = 255 */
#define IPPROTO_RAW_VAL 255

/* Event types */
enum event_type {
	EV_SOCK_CREATE  = 1,
	EV_SOCK_RELEASE = 2,
	EV_BIND4        = 3,
	EV_BIND6        = 4,
};

/* Ringbuf event */
struct event {
	__u8  type;		/* enum event_type */
	__u8  allowed;		/* 1=allowed, 0=denied (for sock_create) */
	__u8  _pad[2];
	__u32 pid;
	__u32 family;		/* AF_INET, AF_INET6 */
	__u32 sock_type;	/* SOCK_STREAM, SOCK_DGRAM, SOCK_RAW */
	__u32 protocol;
	__u32 src_ip4;		/* for bind4: bound IPv4 */
	__u32 src_ip6[4];	/* for bind6: bound IPv6 */
	__u16 src_port;		/* for bind: bound port (host byte order) */
	__u16 _pad2;
	__u64 ts_ns;		/* timestamp (ktime) */
	char  comm[TASK_COMM_LEN];
};

#define DEMO_CGROUP "/sys/fs/cgroup/cg-sock-demo"

#endif /* __CGROUP_SOCK_H */
