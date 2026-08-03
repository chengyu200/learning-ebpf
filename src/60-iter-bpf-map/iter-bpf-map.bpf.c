// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 60-iter-bpf-map: BPF 内核态 — iter/bpf_map 遍历所有 BPF map。
 *
 * 输出每个 map 的 id、type、key_size、value_size、max_entries、name。
 * 类似 bpftool map show，但在 BPF 侧实现。
 *
 * 注意：iter/bpf_map 遍历的是系统中所有 map（不限于本程序的 map）。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("iter/bpf_map")
int dump_bpf_map(struct bpf_iter__bpf_map *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct bpf_map *map = ctx->map;

	if (map == NULL)
		return 0;

	if (ctx->meta->seq_num == 0)
		BPF_SEQ_PRINTF(seq, "%-8s %-10s %-10s %-12s %-12s %s\n",
			       "id", "type", "key_sz", "value_sz", "max_entries", "name");

	/* 读取 map 属性：id 是 bpf_map 内部的，type/key_size 等通过 BPF_CORE_READ */
	BPF_SEQ_PRINTF(seq, "%-8d %-10d %-10d %-12d %-12d %s\n",
		       map->id,
		       BPF_CORE_READ(map, map_type),
		       BPF_CORE_READ(map, key_size),
		       BPF_CORE_READ(map, value_size),
		       BPF_CORE_READ(map, max_entries),
		       BPF_CORE_READ(map, name));

	return 0;
}
