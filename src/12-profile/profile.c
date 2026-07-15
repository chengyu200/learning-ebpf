// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Meta Platforms, Inc. */
/* 12-profile: C user-space (replaces the original Rust loader).
 *
 * Opens a perf_event (PERF_COUNT_SW_CPU_CLOCK) per CPU, attaches the BPF
 * perf_event program to each, aggregates kernel stack traces by signature, and
 * prints the top stacks.  Kernel addresses are symbolized from
 * /proc/kallsyms; user-space addresses are printed as raw hex with pid/comm.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include "profile.h"
#include "profile.skel.h"

#define MAX_AGGS 4096

static struct env {
	int duration_s;
	int top_n;
	int freq;
	bool verbose;
} env = { .duration_s = 5, .top_n = 10, .freq = 99 };

static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

/* ---- /proc/kallsyms symbolization ---- */
struct ksym {
	unsigned long long addr;
	char *name;
};

static struct ksym *ksyms;
static int ksym_cnt;

static int ksym_cmp(const void *a, const void *b)
{
	unsigned long long x = ((const struct ksym *)a)->addr;
	unsigned long long y = ((const struct ksym *)b)->addr;
	return (x > y) - (x < y);
}

static void load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[256], type, *name;
	unsigned long long addr;
	int cap = 1 << 20; /* upper bound on lines */

	if (!f)
		return;
	ksyms = calloc(cap, sizeof(*ksyms));
	if (!ksyms) { fclose(f); return; }

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%llx %c %ms", &addr, &type, &name) != 3)
			continue;
		if (ksym_cnt >= cap)
			break;
		ksyms[ksym_cnt].addr = addr;
		ksyms[ksym_cnt].name = name; /* %m allocates */
		ksym_cnt++;
	}
	fclose(f);
	qsort(ksyms, ksym_cnt, sizeof(*ksyms), ksym_cmp);
}

static const char *ksym_name(unsigned long long addr, unsigned long long *off)
{
	int lo = 0, hi = ksym_cnt - 1, mid;
	*off = 0;
	if (!ksym_cnt || addr < ksyms[0].addr)
		return "[unknown]";
	while (lo < hi) {
		mid = lo + (hi - lo + 1) / 2;
		if (ksyms[mid].addr <= addr)
			lo = mid;
		else
			hi = mid - 1;
	}
	*off = addr - ksyms[lo].addr;
	return ksyms[lo].name;
}

/* ---- stack aggregation ---- */
struct agg {
	unsigned long long sig;
	int count;
	int pid;
	char comm[16];
	int kdepth;
	unsigned long long kstack[MAX_STACK_DEPTH];
	int udepth;
	unsigned long long ustack[MAX_STACK_DEPTH];
};

static struct agg aggs[MAX_AGGS];
static int agg_cnt;

static unsigned long long stack_sig(const unsigned long long *st, int n)
{
	unsigned long long h = 5381;
	for (int i = 0; i < n; i++)
		h = (h * 33) ^ st[i];
	return h;
}

static int agg_cmp(const void *a, const void *b)
{
	return ((const struct agg *)b)->count - ((const struct agg *)a)->count;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct stacktrace_event *e = data;
	int kd = e->kstack_sz / sizeof(unsigned long long);
	int ud = e->ustack_sz / sizeof(unsigned long long);
	unsigned long long sig;
	int i;

	if (kd <= 0)
		return 0;
	sig = stack_sig(e->kstack, kd);

	for (i = 0; i < agg_cnt; i++) {
		if (aggs[i].sig == sig) {
			aggs[i].count++;
			return 0;
		}
	}
	if (agg_cnt >= MAX_AGGS)
		return 0;

	aggs[agg_cnt].sig = sig;
	aggs[agg_cnt].count = 1;
	aggs[agg_cnt].pid = e->pid;
	memcpy(aggs[agg_cnt].comm, e->comm, sizeof(aggs[agg_cnt].comm));
	aggs[agg_cnt].kdepth = kd;
	memcpy(aggs[agg_cnt].kstack, e->kstack, kd * sizeof(unsigned long long));
	aggs[agg_cnt].udepth = ud;
	memcpy(aggs[agg_cnt].ustack, e->ustack, ud * sizeof(unsigned long long));
	agg_cnt++;
	return 0;
}

static void print_results(void)
{
	int i, j, n = agg_cnt < env.top_n ? agg_cnt : env.top_n;

	qsort(aggs, agg_cnt, sizeof(*aggs), agg_cmp);
	printf("\nTop %d kernel stacks (symbolized via /proc/kallsyms):\n", n);
	printf("==================================================================\n");
	for (i = 0; i < n; i++) {
		printf("\n#%d  %d samples  pid=%d comm=%s\n",
		       i + 1, aggs[i].count, aggs[i].pid, aggs[i].comm);
		for (j = 0; j < aggs[i].kdepth; j++) {
			unsigned long long off;
			const char *sym = ksym_name(aggs[i].kstack[j], &off);
			printf("    %016llx %s+0x%llx\n", aggs[i].kstack[j], sym, off);
		}
		if (aggs[i].udepth > 0) {
			printf("  (user-space stack, %d frames, shown raw):\n", aggs[i].udepth);
			for (j = 0; j < aggs[i].udepth && j < 8; j++)
				printf("    %016llx\n", aggs[i].ustack[j]);
		}
	}
}

int main(int argc, char **argv)
{
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	int *pefds = calloc(ncpu, sizeof(int));
	struct bpf_link **links = calloc(ncpu, sizeof(*links));
	struct ring_buffer *rb = NULL;
	struct profile_bpf *skel;
	int err, i;

	/* simple args: duration topN freq */
	if (argc > 1) env.duration_s = atoi(argv[1]);
	if (argc > 2) env.top_n = atoi(argv[2]);
	if (argc > 3) env.freq = atoi(argv[3]);

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = profile_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		err = 1;
		goto out;
	}

	for (i = 0; i < ncpu; i++) {
		struct perf_event_attr attr = {
			.size = sizeof(attr),
			.type = PERF_TYPE_SOFTWARE,
			.config = PERF_COUNT_SW_CPU_CLOCK,
			.sample_type = PERF_SAMPLE_RAW,
			.freq = 1,
			.sample_freq = env.freq,
			.disabled = 1,
			.exclude_kernel = 0,
			.exclude_user = 0,
		};
		pefds[i] = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (pefds[i] < 0) {
			fprintf(stderr, "perf_event_open on cpu %d failed: %s\n",
				i, strerror(errno));
			err = -errno;
			goto cleanup;
		}
		links[i] = bpf_program__attach_perf_event(skel->progs.profile, pefds[i]);
		if (!links[i]) {
			fprintf(stderr, "attach_perf_event on cpu %d failed: %s\n",
				i, strerror(errno));
			err = -errno;
			goto cleanup;
		}
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	load_kallsyms();

	printf("Profiling for %d seconds at %d Hz across %d cpus...\n",
	       env.duration_s, env.freq, ncpu);
	for (i = 0; i < env.duration_s && !exiting; i++)
		ring_buffer__poll(rb, 1000);
	if (!exiting)
		while (ring_buffer__poll(rb, 0) > 0)
			;

	print_results();

cleanup:
	ring_buffer__free(rb);
	for (i = 0; i < ncpu; i++) {
		if (links[i]) bpf_link__destroy(links[i]);
		if (pefds[i] >= 0) close(pefds[i]);
	}
	profile_bpf__destroy(skel);
out:
	free(pefds);
	free(links);
	return err < 0 ? -err : 0;
}
