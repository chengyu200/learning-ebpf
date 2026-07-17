// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC */
/* 33-funclatency: function latency histogram (kprobe + kretprobe).
 * The target function is chosen at attach time in user space; the BPF code is
 * generic (attaches to a dummy symbol that user space overrides via
 * bpf_program__attach_kprobe with an explicit function name).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "funclatency.h"
#include "bits.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile pid_t targ_tgid = 0;
const volatile int units = NSEC;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, u32);
	__type(value, u64);
} starts SEC(".maps");

__u64 hist[MAX_SLOTS] = {};

static __always_inline void entry(void)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 pid = id;
	u64 nsec;

	if (targ_tgid && targ_tgid != tgid)
		return;
	nsec = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
}

static __always_inline void exit_fn(void)
{
	u64 *start, nsec, id, delta, slot;
	u32 pid;

	id = bpf_get_current_pid_tgid();
	pid = id;
	start = bpf_map_lookup_elem(&starts, &pid);
	if (!start)
		return;

	delta = bpf_ktime_get_ns() - *start;
	bpf_map_delete_elem(&starts, &pid);

	switch (units) {
	case USEC: delta /= 1000; break;
	case MSEC: delta /= 1000000; break;
	default: break;
	}

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist[slot], 1);
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe) { entry(); return 0; }

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe) { exit_fn(); return 0; }
