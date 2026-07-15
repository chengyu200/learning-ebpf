// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 7-execsnoop: user-space loader (perf buffer). */
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "execsnoop.h"
#include "execsnoop.skel.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-7d %-7d %-16s %s\n", ts, e->pid, e->ppid, e->comm, e->filename);
}

static void handle_lost(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on cpu %d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct execsnoop_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = execsnoop_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = execsnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8 /* pages */,
			      handle_event, handle_lost, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	printf("%-8s %-7s %-7s %-16s %s\n",
	       "TIME", "PID", "PPID", "COMM", "FILENAME");
	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	perf_buffer__free(pb);
	execsnoop_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
