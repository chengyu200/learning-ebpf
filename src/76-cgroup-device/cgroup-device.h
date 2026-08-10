/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 76-cgroup-device: 共享定义。
 */
#ifndef __CGROUP_DEVICE_H
#define __CGROUP_DEVICE_H

#define TASK_COMM_LEN 16

/* 设备访问操作（与内核 BPF_DEVCG_ACC_* 一致） */
#define BPF_DEVCG_ACC_MKNOD  (1U << 0)
#define BPF_DEVCG_ACC_READ   (1U << 1)
#define BPF_DEVCG_ACC_WRITE  (1U << 2)

/* 设备类型（与内核 BPF_DEVCG_DEV_* 一致） */
#define BPF_DEVCG_DEV_BLOCK  (1U << 0)
#define BPF_DEVCG_DEV_CHAR   (1U << 1)

/* hash map key：设备 major:minor */
struct dev_key {
	__u32 major;
	__u32 minor;
};

/* hash map value：允许的访问操作 mask */
struct dev_val {
	__u32 allow_mask;	/* BPF_DEVCG_ACC_* 的组合 */
};

/* ringbuf 事件 */
struct event {
	__u8  dev_type;	/* BPF_DEVCG_DEV_BLOCK / CHAR */
	__u8  allowed;	/* 1=允许, 0=拒绝 */
	__u8  _pad[2];
	__u32 major;
	__u32 minor;
	__u32 access;	/* BPF_DEVCG_ACC_* */
	__u32 pid;
	char  comm[TASK_COMM_LEN];
};

#define DEMO_CGROUP "/sys/fs/cgroup/cg-dev-demo"

#endif /* __CGROUP_DEVICE_H */
