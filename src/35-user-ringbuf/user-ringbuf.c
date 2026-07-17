// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 35-user-ringbuf: user-space loader.
 *
 * Writes messages into the user ring buffer via bpf_map_update_elem (which
 * for a USER_RINGBUF appends); the BPF perf_event program drains them
 * periodically with bpf_user_ringbuf_drain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "user-ringbuf.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct user_ringbuf_bpf *skel;
	int err = 0, i, ncpu, pe_fd = -1;
	struct perf_event_attr attr = {
		.size = sizeof(attr),
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
		.sample_type = PERF_SAMPLE_RAW,
		.freq = 1, .sample_freq = 5, .disabled = 1,
	};

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = user_ringbuf_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }
	err = user_ringbuf_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach failed\n"); goto cleanup; }

	ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	for (i = 0; i < ncpu; i++) {
		int fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) continue;
		struct bpf_link *l = bpf_program__attach_perf_event(skel->progs.drain_user_ring, fd);
		if (l && i == 0) { link = l; pe_fd = fd; }
		else if (l) bpf_link__destroy(l);
		else close(fd);
	}

	printf("user-ringbuf demo; writing messages... Ctrl-C\n");
	printf("(watch trace_pipe for kernel-side drain output)\n");
	int seq = 0;
	int ur_fd = bpf_map__fd(skel->maps.user_ring);
	while (!exiting) {
		char msg[32];
		int n = snprintf(msg, sizeof(msg), "hello %d", seq++);
		/* For a USER_RINGBUF map, bpf_map_update_elem appends a record. */
		bpf_map_update_elem(ur_fd, msg, &n, BPF_ANY);
		sleep(1);
	}

cleanup:
	if (link) bpf_link__destroy(link);
	if (pe_fd >= 0) close(pe_fd);
	user_ringbuf_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
