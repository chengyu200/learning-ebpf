// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 4-opensnoop: user-space loader. */
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <argp.h>
#include <bpf/libbpf.h>
#include "opensnoop.h"
#include "opensnoop.skel.h"

static struct env {
	pid_t target_pid;
	bool failed_only;
	bool verbose;
} env;

const char *argp_program_version = "opensnoop 0.1";
const char argp_program_doc[] =
"Trace openat() syscalls.\n\n"
"USAGE: ./opensnoop [--pid PID] [--failed] [-v]\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "failed", 'f', NULL, 0, "Show only failed opens" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		env.target_pid = strtol(arg, NULL, 10);
		break;
	case 'f':
		env.failed_only = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-7d %-7d %-7d %-16s %s\n",
	       ts, e->pid, e->uid, e->ret, e->comm, e->filename);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct opensnoop_bpf *skel;
	int err;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = opensnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Configure BPF-side globals before loading. */
	skel->rodata->target_pid = env.target_pid;
	skel->rodata->failed_only = env.failed_only;

	err = opensnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	err = opensnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("%-8s %-7s %-7s %-7s %-16s %s\n",
	       "TIME", "PID", "UID", "RET", "COMM", "FILENAME");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	opensnoop_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
