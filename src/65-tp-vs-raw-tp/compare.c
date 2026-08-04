// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 65-tp-vs-raw-tp: 用户态加载器。
 *
 * 加载两个 BPF 程序（tracepoint + raw_tracepoint），
 * 每秒读取 per-CPU 统计并打印性能对比。
 *
 * 用法：
 *   sudo ./compare [duration_sec]   # 默认 10 秒
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "compare.h"
#include "compare.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* 读取 per-CPU map 并汇总所有 CPU 的值 */
static struct stats read_stats(int map_fd)
{
	struct stats total = {};
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	struct stats *vals = calloc(ncpu, sizeof(struct stats));
	__u32 key = 0;

	if (!vals)
		return total;

	if (bpf_map_lookup_elem(map_fd, &key, vals) == 0) {
		for (int i = 0; i < ncpu; i++) {
			total.count += vals[i].count;
			total.total_ns += vals[i].total_ns;
		}
	}
	free(vals);
	return total;
}

int main(int argc, char **argv)
{
	struct compare_bpf *skel;
	int err = 0;
	int duration = 10;

	if (argc > 1)
		duration = atoi(argv[1]);

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	skel = compare_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = compare_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach: %d\n", err);
		goto cleanup;
	}

	int tp_fd = bpf_map__fd(skel->maps.tp_stats);
	int raw_fd = bpf_map__fd(skel->maps.raw_tp_stats);

	printf("Loading BPF programs (tracepoint + raw_tracepoint)...\n");
	printf("Both attached to sched/sched_switch. Measuring for %d seconds...\n\n", duration);
	printf("%-6s  %-12s %12s %12s %12s %12s %12s\n",
	       "", "TRACEPOINT", "", "", "RAW_TRACEPOINT", "", "");
	printf("%-6s  %12s %12s %12s %12s %12s %12s\n",
	       "sec", "events", "total(us)", "ns/evt",
	       "events", "total(us)", "ns/evt");
	printf("──────  ──────────── ──────────── ──────────── ──────────── ──────────── ────────────\n");

	struct stats tp_prev = {}, raw_prev = {};

	for (int sec = 1; sec <= duration && !exiting; sec++) {
		sleep(1);

		struct stats tp_now = read_stats(tp_fd);
		struct stats raw_now = read_stats(raw_fd);

		__u64 tp_delta_count = tp_now.count - tp_prev.count;
		__u64 tp_delta_ns = tp_now.total_ns - tp_prev.total_ns;
		__u64 raw_delta_count = raw_now.count - raw_prev.count;
		__u64 raw_delta_ns = raw_now.total_ns - raw_prev.total_ns;

		__u64 tp_per = tp_delta_count ? tp_delta_ns / tp_delta_count : 0;
		__u64 raw_per = raw_delta_count ? raw_delta_ns / raw_delta_count : 0;

		printf("%-6d  %12llu %12llu %12llu %12llu %12llu %12llu",
		       sec,
		       tp_delta_count, tp_delta_ns / 1000, tp_per,
		       raw_delta_count, raw_delta_ns / 1000, raw_per);

		if (tp_per > 0 && raw_per > 0) {
			if (raw_per < tp_per) {
				printf("  (raw_tp %.1f%% faster)",
				       (double)(tp_per - raw_per) / (double)tp_per * 100.0);
			} else {
				printf("  (tp %.1f%% faster)",
				       (double)(raw_per - tp_per) / (double)raw_per * 100.0);
			}
		}
		printf("\n");

		tp_prev = tp_now;
		raw_prev = raw_now;
	}

	/* 最终总结 */
	struct stats tp_final = read_stats(tp_fd);
	struct stats raw_final = read_stats(raw_fd);

	printf("\n");
	printf("═══════════════════════════════════════════════════════════════\n");
	printf("  Summary\n");
	printf("═══════════════════════════════════════════════════════════════\n");
	printf("  TRACEPOINT:     %llu events, %.3f ms total, %.1f ns/evt\n",
	       tp_final.count, tp_final.total_ns / 1000000.0,
	       tp_final.count ? (double)tp_final.total_ns / tp_final.count : 0);
	printf("  RAW_TRACEPOINT: %llu events, %.3f ms total, %.1f ns/evt\n",
	       raw_final.count, raw_final.total_ns / 1000000.0,
	       raw_final.count ? (double)raw_final.total_ns / raw_final.count : 0);

	if (tp_final.count > 0 && raw_final.count > 0) {
		double tp_avg = (double)tp_final.total_ns / tp_final.count;
		double raw_avg = (double)raw_final.total_ns / raw_final.count;
		if (tp_avg > raw_avg) {
			printf("  RAW_TP is %.1f%% faster (%.1f vs %.1f ns/evt)\n",
			       (tp_avg - raw_avg) / tp_avg * 100, raw_avg, tp_avg);
		} else {
			printf("  TP is %.1f%% faster (%.1f vs %.1f ns/evt)\n",
			       (raw_avg - tp_avg) / raw_avg * 100, tp_avg, raw_avg);
		}
	}

	printf("  Events match: %s\n",
	       tp_final.count == raw_final.count ? "YES" : "NO (unexpected!)");
	printf("═══════════════════════════════════════════════════════════════\n");

cleanup:
	compare_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
