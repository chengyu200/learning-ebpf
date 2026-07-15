// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 10-hardirqs: user-space loader. Dumps per-IRQ stats on exit. */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hardirqs.h"
#include "hardirqs.skel.h"

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

static void print_stats(struct hardirqs_bpf *skel)
{
	__u32 irq, *prev_key = NULL;
	unsigned long long total_all = 0, count_all = 0;

	printf("\n%-8s %-10s %s\n", "IRQ", "COUNT", "TOTAL(ms)");
	printf("-----------------------------------\n");

	while (bpf_map__get_next_key(skel->maps.irq_total, prev_key,
				     &irq, sizeof(irq)) == 0) {
		struct irq_stat stat = {};

		if (bpf_map__lookup_elem(skel->maps.irq_total, &irq,
					 sizeof(irq), &stat, sizeof(stat), 0) == 0) {
			printf("%-8u %-10llu %.2f\n",
			       irq, stat.count, stat.total_ns / 1000000.0);
			total_all += stat.total_ns;
			count_all += stat.count;
		}
		prev_key = &irq;
	}

	printf("-----------------------------------\n");
	printf("%-8s %-10llu %.2f\n", "TOTAL", count_all, total_all / 1000000.0);
}

int main(int argc, char **argv)
{
	struct hardirqs_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = hardirqs_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = hardirqs_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Counting hard interrupts... Ctrl-C to print stats.\n");
	while (!exiting)
		sleep(1);

	print_stats(skel);

cleanup:
	hardirqs_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
