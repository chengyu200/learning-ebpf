// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Wenbo Zhang */
/* 17-biopattern: user-space loader. Dumps per-device stats periodically. */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "biopattern.h"
#include "biopattern.skel.h"

static struct env {
	int interval;
	bool verbose;
} env = { .interval = 2 };

const char *argp_program_version = "biopattern 0.1";
const char argp_program_doc[] =
"Count random/sequential disk I/O.\n\n"
"USAGE: ./biopattern [-i SEC]\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "SEC", 0, "Print interval (default 2)" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'i': env.interval = atoi(arg); break;
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

static void print_stats(struct biopattern_bpf *skel)
{
	__u32 dev, *prev = NULL;
	struct tm *tm;
	char ts[32];
	time_t t = time(NULL);

	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("\n%-8s %-10s %-10s %-10s %s\n", "TIME", "DISK", "SEQUENTIAL", "RANDOM", "BYTES");

	while (bpf_map__get_next_key(skel->maps.counters, prev, &dev, sizeof(dev)) == 0) {
		struct counter c = {};

		if (bpf_map__lookup_elem(skel->maps.counters, &dev, sizeof(dev),
					 &c, sizeof(c), 0) == 0) {
			printf("%-8s %-10u %-10llu %-10llu %llu\n",
			       ts, dev, c.sequential, c.random, c.bytes);
			/* reset after printing */
			c = (struct counter){ .last_sector = c.last_sector };
			bpf_map__update_elem(skel->maps.counters, &dev, sizeof(dev),
					     &c, sizeof(c), BPF_EXIST);
		}
		prev = &dev;
	}
}

int main(int argc, char **argv)
{
	struct biopattern_bpf *skel;
	int err;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = biopattern_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = biopattern_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Counting block I/O patterns... Ctrl-C to end.");
	while (!exiting) {
		sleep(env.interval);
		print_stats(skel);
	}

cleanup:
	biopattern_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
