// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Chen Tao */
/* 15-javagc: capture Java GC duration via USDT probes.
 *
 * Hooks the HotSpot USDT probes gc__begin/gc__end (and mem__pool_gc_begin/end)
 * in libjvm.so, pairs start/end per pid, and emits durations above a threshold
 * through a perf event array.
 * Teaches: USDT (user statically-defined tracepoints) programs in libbpf.
 *
 * NOTE: this example is compile-only on hosts without a JVM; running it needs a
 * Java process with HotSpot USDT support (see README.md).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "javagc.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key, __u32);
	__type(value, struct data_t);
} data_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, int);
} perf_map SEC(".maps");

const volatile __u32 time = 0;

static int gc_start(struct pt_regs *ctx)
{
	struct data_t data = {};

	data.cpu = bpf_get_smp_processor_id();
	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&data_map, &data.pid, &data, 0);
	return 0;
}

static int gc_end(struct pt_regs *ctx)
{
	struct data_t data = {};
	struct data_t *p;
	__u32 val;

	data.cpu = bpf_get_smp_processor_id();
	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.ts = bpf_ktime_get_ns();
	p = bpf_map_lookup_elem(&data_map, &data.pid);
	if (!p)
		return 0;

	val = data.ts - p->ts;
	if (val > time) {
		data.ts = val;
		bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
	}
	bpf_map_delete_elem(&data_map, &data.pid);
	return 0;
}

SEC("usdt")
int handle_gc_start(struct pt_regs *ctx) { return gc_start(ctx); }

SEC("usdt")
int handle_gc_end(struct pt_regs *ctx) { return gc_end(ctx); }

SEC("usdt")
int handle_mem_pool_gc_start(struct pt_regs *ctx) { return gc_start(ctx); }

SEC("usdt")
int handle_mem_pool_gc_end(struct pt_regs *ctx) { return gc_end(ctx); }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
