// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 9-runqlat: user-space loader. Prints the histogram on exit. */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "runqlat.h"
#include "runqlat.skel.h"

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

static void print_histogram(struct runqlat_bpf *skel)
{
	int i, max_slot = -1;
	__u64 counts[MAX_SLOTS] = {};
	__u64 max_val = 0;

	for (i = 0; i < MAX_SLOTS; i++) {
		__u32 key = i;
		__u64 val = 0;

		bpf_map__lookup_elem(skel->maps.hist, &key, sizeof(key), &val, sizeof(val), 0);
		counts[i] = val;
		if (val > 0)
			max_slot = i;
		if (val > max_val)
			max_val = val;
	}

	if (max_slot < 0) {
		printf("No samples collected.\n");
		return;
	}

	printf("\nrunqueue latency (microseconds):\n");
	printf("%-12s %-10s : %-8s |%-s\n", "range", "count", "percent", "graph");
	for (i = 0; i <= max_slot; i++) {
		int stars, j;
		double pct = max_val ? (100.0 * counts[i] / max_val) : 0.0;

		if (i == 0)
			printf("%-12s ", "0");
		else
			printf("2^%-2d - 2^%-2d ", i - 1, i);
		printf("%-10llu : %7.2f%% |", (unsigned long long)counts[i], pct);
		stars = (int)(pct / 2.0);
		for (j = 0; j < stars && j < 40; j++)
			printf("*");
		printf("\n");
	}
}

int main(int argc, char **argv)
{
	struct runqlat_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = runqlat_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = runqlat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Collecting run queue latency... Ctrl-C to print the histogram.\n");
	while (!exiting)
		sleep(1);

	print_histogram(skel);

cleanup:
	runqlat_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
