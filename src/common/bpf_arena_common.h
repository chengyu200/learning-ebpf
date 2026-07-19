/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* BPF arena 地址空间修饰符（参考内核 selftests/bpf/bpf_arena_common.h） */
#ifndef __BPF_ARENA_COMMON_H
#define __BPF_ARENA_COMMON_H

/* __arena: 将变量放入 arena 地址空间（.addr_space.1 段） */
#define __arena __attribute__((address_space(1)))

/* __arena_global: 全局变量放入 arena 地址空间 */
#define __arena_global __attribute__((section(".addr_space.1")))

#endif /* __BPF_ARENA_COMMON_H */
