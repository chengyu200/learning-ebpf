// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Hengqi Chen */
/* 14-tcpstates: user-space loader. */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "tcpstates.h"
#include "tcpstates.skel.h"

static struct env {
	__u16 sport;
	__u16 dport;
	bool filter_sport;
	bool filter_dport;
	bool verbose;
} env;

const char *argp_program_version = "tcpstates 0.1";
const char argp_program_doc[] =
"Trace TCP state changes.\n"
"\n"
"USAGE: ./tcpstates [--sport PORT] [--dport PORT] [-v]\n";

static const struct argp_option opts[] = {
	{ "sport", 's', "PORT", 0, "Filter by source port" },
	{ "dport", 'd', "PORT", 0, "Filter by destination port" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 's':
		env.sport = strtol(arg, NULL, 10);
		env.filter_sport = true;
		break;
	case 'd':
		env.dport = strtol(arg, NULL, 10);
		env.filter_dport = true;
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

static const char *state_name(__u8 s)
{
	switch (s) {
	case 1: return "ESTABLISHED";
	case 2: return "SYN_SENT";
	case 3: return "SYN_RECV";
	case 4: return "FIN_WAIT1";
	case 5: return "FIN_WAIT2";
	case 6: return "TIME_WAIT";
	case 7: return "CLOSE";
	case 8: return "CLOSE_WAIT";
	case 9: return "LAST_ACK";
	case 10: return "LISTEN";
	case 11: return "CLOSING";
	default: return "?";
	}
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32], s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->family == AF_INET) {
		inet_ntop(AF_INET, &e->saddr[0], s, sizeof(s));
		inet_ntop(AF_INET, &e->daddr[0], d, sizeof(d));
	} else {
		inet_ntop(AF_INET6, e->saddr, s, sizeof(s));
		inet_ntop(AF_INET6, e->daddr, d, sizeof(d));
	}

	printf("%-8s %-7d %16llu.%06llu %5llu.%06llu %-12s -> %-12s %s:%d -> %s:%d\n",
	       ts, e->pid,
	       e->ts_us / 1000000, e->ts_us % 1000000,
	       e->delta_us / 1000000, e->delta_us % 1000000,
	       state_name(e->oldstate), state_name(e->newstate),
	       s, e->sport, d, ntohs(e->dport));
}

static void handle_lost(void *ctx, int cpu, __u64 cnt)
{
	fprintf(stderr, "lost %llu events on cpu %d\n", cnt, cpu);
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct tcpstates_bpf *skel;
	int err;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = tcpstates_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->filter_by_sport = env.filter_sport;
	skel->rodata->filter_by_dport = env.filter_dport;
	skel->rodata->target_family = 0;
	if (env.filter_sport) {
		__u16 v = 1;
		bpf_map__update_elem(skel->maps.sports, &env.sport, sizeof(env.sport),
				     &v, sizeof(v), BPF_ANY);
	}
	if (env.filter_dport) {
		__u16 v = 1;
		bpf_map__update_elem(skel->maps.dports, &env.dport, sizeof(env.dport),
				     &v, sizeof(v), BPF_ANY);
	}

	err = tcpstates_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}
	err = tcpstates_bpf__attach(skel);
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

	printf("%-8s %-7s %-21s %-19s %-14s %s\n",
	       "TIME", "PID", "TIMESTAMP(us)", "DELTA(us)", "OLDSTATE", "-> NEWSTATE ADDR");
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
	tcpstates_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
