// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Chen Tao */
/* 15-javagc: user-space loader.
 *
 * Attaches the USDT programs to HotSpot probes in libjvm.so and prints GC
 * durations.  Requires a running Java process (HotSpot) with USDT support.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "javagc.h"
#include "javagc.skel.h"

static struct env {
	pid_t pid;
	const char *libjvm;
	__u32 threshold_ns;
	bool verbose;
} env = { .pid = 0, .libjvm = "libjvm.so", .threshold_ns = 0 };

const char *argp_program_version = "javagc 0.1";
const char argp_program_doc[] =
"Trace Java GC duration via USDT.\n"
"\n"
"USAGE: ./javagc --pid PID --libjvm /path/to/libjvm.so [--threshold-ns N]\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Java process PID to trace" },
	{ "libjvm", 'l', "PATH", 0, "Path to libjvm.so" },
	{ "threshold-ns", 't', "NS", 0, "Only report GCs longer than this (ns)" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p': env.pid = strtol(arg, NULL, 10); break;
	case 'l': env.libjvm = arg; break;
	case 't': env.threshold_ns = strtol(arg, NULL, 10); break;
	case 'v': env.verbose = true; break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = argp_program_doc };

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct data_t *d = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-7d %-5d %llu ns\n", ts, d->pid, d->cpu, d->ts);
}

static void handle_lost(void *ctx, int cpu, __u64 cnt)
{
	fprintf(stderr, "lost %llu events on cpu %d\n", cnt, cpu);
}

#define ATTACH_USDT(prog, name) \
	do { \
		LIBBPF_OPTS(bpf_usdt_opts, uopts, .usdt_cookie = 0); \
		struct bpf_link *l = bpf_program__attach_usdt( \
			skel->progs.prog, env.pid, env.libjvm, \
			"hotspot", name, &uopts); \
		if (!l) { \
			fprintf(stderr, "failed to attach usdt " name ": %s\n", \
				strerror(errno)); \
			goto cleanup; \
		} \
		links[nlinks++] = l; \
	} while (0)

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct javagc_bpf *skel;
	struct bpf_link *links[4];
	int nlinks = 0, err, i;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = javagc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->time = env.threshold_ns;

	err = javagc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	ATTACH_USDT(handle_gc_start, "gc__begin");
	ATTACH_USDT(handle_gc_end, "gc__end");
	ATTACH_USDT(handle_mem_pool_gc_start, "mem__pool_gc_begin");
	ATTACH_USDT(handle_mem_pool_gc_end, "mem__pool_gc_end");

	pb = perf_buffer__new(bpf_map__fd(skel->maps.perf_map), 8,
			      handle_event, handle_lost, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	printf("%-8s %-7s %-5s %s\n", "TIME", "PID", "CPU", "GC_DURATION");
	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	perf_buffer__free(pb);
	for (i = 0; i < nlinks; i++)
		bpf_link__destroy(links[i]);
	javagc_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
