// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 10-hardirqs: count time spent in hard interrupts, per IRQ.
 *
 * Kernel side: on irq_handler_entry record a start timestamp keyed by
 * (cpu, irq); on irq_handler_exit compute the duration and accumulate it, plus an
 * invocation count, in a hash map keyed by irq number.
 * Teaches: interrupt tracepoints (tp/irq/...), per-cpu state with a hash map,
 * accumulating into a keyed map, and dumping a hash map from user space with
 * bpf_map__get_next_key.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hardirqs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Per-(cpu, irq) in-flight start timestamp. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);            /* (cpu << 32) | irq */
	__type(value, u64);          /* start timestamp (ns) */
} start SEC(".maps");

/* Accumulated time and count per IRQ. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, u32);            /* irq number */
	__type(value, struct irq_stat);
} irq_total SEC(".maps");

SEC("tp/irq/irq_handler_entry")
int handle_irq_entry(struct trace_event_raw_irq_handler_entry *ctx)
{
	u32 irq = ctx->irq;
	u32 cpu = bpf_get_smp_processor_id();
	u64 key = ((u64)cpu << 32) | (u64)irq;
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
	return 0;
}

SEC("tp/irq/irq_handler_exit")
int handle_irq_exit(struct trace_event_raw_irq_handler_exit *ctx)
{
	u32 irq = ctx->irq;
	u32 cpu = bpf_get_smp_processor_id();
	u64 key = ((u64)cpu << 32) | (u64)irq;
	u64 *tsp, now, delta;
	struct irq_stat *statp, init = {};

	tsp = bpf_map_lookup_elem(&start, &key);
	if (!tsp)
		return 0;

	now = bpf_ktime_get_ns();
	delta = now - *tsp;
	bpf_map_delete_elem(&start, &key);

	statp = bpf_map_lookup_elem(&irq_total, &irq);
	if (statp) {
		statp->total_ns += delta;
		statp->count += 1;
	} else {
		init.total_ns = delta;
		init.count = 1;
		bpf_map_update_elem(&irq_total, &irq, &init, BPF_NOEXIST);
	}
	return 0;
}
