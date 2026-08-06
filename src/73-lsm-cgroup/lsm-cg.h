/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 73-lsm-cgroup: cgroup 级 LSM 安全策略共享定义。
 */
#ifndef __LSM_CG_H
#define __LSM_CG_H

#define BLOCK_PORT 9999
#define BLOCK_IP   0x0100007f  /* 127.0.0.1 网络字节序 */

#define DEMO_CGROUP "/sys/fs/cgroup/lsm-cgroup-demo"

#endif /* __LSM_CG_H */
