// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-fsession: 用户态加载器。
 *
 * 加载 FSESSION BPF 程序，轮询 ringbuf 收集延迟数据，
 * Ctrl-C 时输出统计摘要 + log2 直方图。
 *
 * 用法：
 *   sudo ./fsession [duration_sec]   # 默认持续到 Ctrl-C
 *   # 另开终端：cat /etc/hostname, ls, curl ...
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "fsession.h"
#include "fsession.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* 统计数据 */
static __u64 total_count = 0;
static __u64 total_ns = 0;
static __u64 max_ns = 0;
static __u64 min_ns = ~0ULL;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	total_count++;
	total_ns += e->latency_ns;
	if (e->latency_ns > max_ns)
		max_ns = e->latency_ns;
	if (e->latency_ns < min_ns)
		min_ns = e->latency_ns;

	/* 打印前 20 个事件（详细），之后只统计 */
	if (total_count <= 20) {
		printf("%-6llu  pid=%-7d  %-16s  %llu ns",
		       total_count, e->pid, e->comm, e->latency_ns);
		if (e->latency_ns > 1000000)
			printf(" (%.2f ms)", e->latency_ns / 1000000.0);
		else if (e->latency_ns > 1000)
			printf(" (%.2f us)", e->latency_ns / 1000.0);
		printf("\n");
	} else if (total_count == 21) {
		printf("... (suppressing further output, collecting stats)\n");
	}

	return 0;
}

static void print_stats(struct fsession_bpf *skel)
{
	printf("\n");
	printf("═══════════════════════════════════════════════════════════════\n");
	printf("  vfs_read latency statistics (BPF_TRACE_FSESSION)\n");
	printf("═══════════════════════════════════════════════════════════════\n");

	if (total_count == 0) {
		printf("  No samples collected.\n");
		return;
	}

	printf("  Total samples:  %llu\n", total_count);
	printf("  Average:        %.2f ns  (%.2f us)\n",
	       (double)total_ns / total_count,
	       (double)total_ns / total_count / 1000.0);
	printf("  Min:            %llu ns\n", min_ns);
	printf("  Max:            %llu ns  (%.2f us)\n", max_ns, max_ns / 1000.0);

	/* 打印 log2 直方图 */
	printf("\n");
	printf("  log2 latency histogram (ns):\n");
	printf("  %-14s %-10s : %s\n", "range", "count", "graph");

	int max_slot = -1;
	__u64 max_val = 0;
	for (int i = 0; i < MAX_SLOTS; i++) {
		__u64 v = skel->bss->hist[i];
		if (v > 0)
			max_slot = i;
		if (v > max_val)
			max_val = v;
	}

	if (max_slot < 0) {
		printf("  (no histogram data)\n");
		return;
	}

	for (int i = 0; i <= max_slot; i++) {
		__u64 v = skel->bss->hist[i];
		double pct = max_val ? (100.0 * v / max_val) : 0;
		int j, stars = (int)(pct / 2.0);

		if (i == 0)
			printf("  %-14s ", "0");
		else
			printf("  2^%-2d - 2^%-2d   ", i - 1, i);
		printf("%-10llu : %6.2f%% |", v, pct);
		for (j = 0; j < stars && j < 40; j++)
			putchar('*');
		printf("\n");
	}

	printf("═══════════════════════════════════════════════════════════════\n");
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct fsession_bpf *skel;
	int err = 0;
	int duration = 0; /* 0 = 持续到 Ctrl-C */

	if (argc > 1)
		duration = atoi(argv[1]);

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	/* 加载 BPF 骨架 */
	skel = fsession_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* attach（libbpf 自动处理 fsession attach） */
	err = fsession_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* 创建 ringbuf */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	printf("Measuring vfs_read latency via BPF_TRACE_FSESSION...\n");
	printf("Run commands in another terminal (cat, ls, curl) to trigger I/O.\n");
	if (duration > 0)
		printf("Auto-stopping after %d seconds.\n", duration);
	printf("Ctrl-C to stop and view statistics.\n\n");
	printf("%-6s  %-7s  %-16s  %s\n", "#", "PID", "COMM", "LATENCY");

	/* 主循环：按墙钟时间判断超时 */
	time_t start_ts = time(NULL);
	while (!exiting) {
		err = ring_buffer__poll(rb, 1000);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
		if (duration > 0) {
			if (time(NULL) - start_ts >= duration) {
				exiting = 1;
				break;
			}
		}
	}

	/* 排空剩余事件 */
	ring_buffer__poll(rb, 0);

	/* 输出统计 */
	print_stats(skel);

cleanup:
	ring_buffer__free(rb);
	fsession_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
