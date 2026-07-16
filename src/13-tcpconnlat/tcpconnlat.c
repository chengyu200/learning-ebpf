// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
/* 13-tcpconnlat: user-space loader. */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "tcpconnlat.h"
#include "tcpconnlat.skel.h"

static struct env {
	__u64 min_us;
	pid_t pid;
	bool verbose;
} env;

const char *argp_program_version = "tcpconnlat 0.1";
const char argp_program_doc[] =
"Trace TCP connect latency.\n"
"\n"
"USAGE: ./tcpconnlat [--pid PID] [--min-ms MS] [-v]\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "min-ms", 'm', "MS", 0, "Minimum connect latency (ms) to report" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		env.pid = strtol(arg, NULL, 10);
		break;
	case 'm':
		env.min_us = strtol(arg, NULL, 10) * 1000ULL;
		break;
	case 'v':
		env.verbose = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
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

static void print_addr(int af, const struct event *e)
{
	char s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN];

	if (af == AF_INET) {
		inet_ntop(AF_INET, &e->saddr_v4, s, sizeof(s));
		inet_ntop(AF_INET, &e->daddr_v4, d, sizeof(d));
	} else {
		inet_ntop(AF_INET6, e->saddr_v6, s, sizeof(s));
		inet_ntop(AF_INET6, e->daddr_v6, d, sizeof(d));
	}
	printf("%s:%d -> %s:%d", s, e->lport, d, ntohs(e->dport));
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

	printf("%-8s %-7d %7llu.%03llu %-6u ",
	       ts, e->tgid, e->delta_us / 1000, e->delta_us % 1000, e->pid);
	print_addr(e->af, e);
	printf(" %s\n", e->comm);
}

static void handle_lost(void *ctx, int cpu, __u64 cnt)
{
	fprintf(stderr, "lost %llu events on cpu %d\n", cnt, cpu);
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct tcpconnlat_bpf *skel;
	int err;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = tcpconnlat_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->targ_min_us = env.min_us;
	skel->rodata->targ_tgid = env.pid;

	err = tcpconnlat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}
	err = tcpconnlat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8,
			      handle_event, handle_lost, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	printf("%-8s %-7s %-11s %-6s %-22s %s\n",
	       "TIME", "TGID", "LAT(ms)", "PID", "ADDR", "COMM");
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
	tcpconnlat_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
