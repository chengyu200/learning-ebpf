// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Google LLC */
/* 33-funclatency: user-space loader.  Attaches the generic kprobe/kretprobe to
 * an arbitrary function (argv[1]) and prints a latency histogram on exit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "funclatency.h"
#include "funclatency.skel.h"

static char *g_func = "vfs_read";
static int g_units = NSEC;
static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

static void print_hist(struct funclatency_bpf *skel)
{
	int i, max_slot = -1;
	__u64 max_val = 0;

	for (i = 0; i < MAX_SLOTS; i++) {
		__u64 v = skel->bss->hist[i];
		if (v) max_slot = i;
		if (v > max_val) max_val = v;
	}
	if (max_slot < 0) { printf("no samples\n"); return; }

	printf("\nfunction latency (%s):\n", g_units == NSEC ? "ns" :
	       g_units == USEC ? "us" : "ms");
	printf("%-12s %-10s : %s\n", "range", "count", "graph");
	for (i = 0; i <= max_slot; i++) {
		__u64 v = skel->bss->hist[i];
		double pct = max_val ? 100.0 * v / max_val : 0;
		int j, stars = (int)(pct / 2);
		if (i == 0) printf("%-12s ", "0");
		else printf("2^%-2d - 2^%-2d ", i - 1, i);
		printf("%-10llu : %6.2f%% |", v, pct);
		for (j = 0; j < stars && j < 40; j++) putchar('*');
		printf("\n");
	}
}

int main(int argc, char **argv)
{
	struct bpf_link *kp = NULL, *krp = NULL;
	struct funclatency_bpf *skel;
	int err = 0;
	const char *unit_str;

	if (argc > 1) g_func = argv[1];
	if (argc > 2) {
		if (!strcmp(argv[2], "us")) g_units = USEC;
		else if (!strcmp(argv[2], "ms")) g_units = MSEC;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = funclatency_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
	skel->rodata->targ_tgid = 0;
	skel->rodata->units = g_units;
	err = funclatency_bpf__load(skel);
	if (err) { fprintf(stderr, "load failed\n"); goto cleanup; }

	LIBBPF_OPTS(bpf_kprobe_opts, ko);
	kp = bpf_program__attach_kprobe_opts(skel->progs.dummy_kprobe, g_func, &ko);
	if (!kp) { fprintf(stderr, "attach kprobe %s: %s\n", g_func, strerror(errno));
		   err = -errno; goto cleanup; }
	LIBBPF_OPTS(bpf_kprobe_opts, kro, .retprobe = 1);
	krp = bpf_program__attach_kprobe_opts(skel->progs.dummy_kretprobe, g_func, &kro);
	if (!krp) { fprintf(stderr, "attach kretprobe %s: %s\n", g_func, strerror(errno));
		   err = -errno; goto cleanup; }

	printf("measuring %s latency... Ctrl-C to print\n", g_func);
	while (!exiting) sleep(1);

	print_hist(skel);

cleanup:
	if (krp) bpf_link__destroy(krp);
	if (kp) bpf_link__destroy(kp);
	funclatency_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
