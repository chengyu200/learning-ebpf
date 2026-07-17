// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 49-hid: trace HID (human-interface-device) reports via kprobe on
 * hidraw_report_event.  Sends {pid, minor, ts} to user space via ringbuf.
 * Teaches: tracing HID input path; the kernel has full HID-BPF support
 * (CONFIG_HID_BPF=y) but this example uses a kprobe for portability.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hid.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/hidraw_report_event")
int BPF_KPROBE(handle_hid_report, void *hidraw, __u8 *buf, size_t len)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ts_ns = bpf_ktime_get_ns();
	e->minor = 0; /* would read hidraw->minor via BPF_CORE_READ */

	bpf_ringbuf_submit(e, 0);
	return 0;
}
