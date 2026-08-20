// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 84-iter-memcg: 用户态加载器 — 遍历所有 mem_cgroup。
 *
 * 流程：
 *   1. 加载 BPF skeleton
 *   2. 设置 target_pid（默认自身 PID）
 *   3. attach tracepoint sys_enter_openat
 *   4. 触发 openat（打开 /dev/null）→ BPF 遍历所有 mem_cgroup
 *   5. 消费 ringbuf，打印每个 mem_cgroup 的信息
 *   6. Ctrl-C 清理
 *
 * 用法：
 *   sudo ./iter-memcg
 *   sudo ./iter-memcg --pid 1234   # 指定 PID
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iter-memcg.h"
#include "iter-memcg.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct memcg_event *e = data;
	char mem_str[32], swap_str[32];

	/* 格式化内存使用量 */
	if (e->memory_usage > 1024 * 1024)
		snprintf(mem_str, sizeof(mem_str), "%llu MB", e->memory_usage / (1024 * 1024));
	else if (e->memory_usage > 1024)
		snprintf(mem_str, sizeof(mem_str), "%llu KB", e->memory_usage / 1024);
	else
		snprintf(mem_str, sizeof(mem_str), "%llu B", e->memory_usage);

	if (e->swap_usage > 1024 * 1024)
		snprintf(swap_str, sizeof(swap_str), "%llu MB", e->swap_usage / (1024 * 1024));
	else if (e->swap_usage > 1024)
		snprintf(swap_str, sizeof(swap_str), "%llu KB", e->swap_usage / 1024);
	else
		snprintf(swap_str, sizeof(swap_str), "%llu B", e->swap_usage);

	printf("  memcg[%llu]  level=%-2u  cgroup=%-40s  memory=%-12s  swap=%-12s\n",
	       e->memcg_id, e->level,
	       e->cgroup_name[0] ? e->cgroup_name : "/",
	       mem_str, swap_str);
	return 0;
}

int main(int argc, char **argv)
{
	struct iter_memcg_bpf *skel;
	struct ring_buffer *ringbuf = NULL;
	int err = 0;
	pid_t target = getpid();

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
			target = atoi(argv[++i]);
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	/* 1. 加载 skeleton */
	skel = iter_memcg_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	/* 2. 设置 target_pid（通过 skeleton bss 直接写入） */
	skel->bss->target_pid = target;

	/* 3. attach tracepoint */
	err = iter_memcg_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach: %d\n", err);
		goto cleanup;
	}

	/* 4. 设置 ringbuf */
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	printf("BPF mem_cgroup iterator attached (target_pid=%d)\n", target);
	printf("Triggering openat to start iteration...\n\n");

	/* 5. 触发 openat（打开 /dev/null） */
	int fd = open("/dev/null", O_RDONLY);
	if (fd >= 0)
		close(fd);

	/* 6. 消费 ringbuf 事件 */
	printf("%-8s  %-7s  %-40s  %-12s  %-12s\n",
	       "memcg_id", "level", "cgroup", "memory", "swap");
	printf("────────  ───────  ──────────────────────────────────────  ────────────  ────────────\n");

	/* 轮询 ringbuf，等待事件到达 */
	for (int i = 0; i < 50 && !exiting; i++) {
		if (ring_buffer__poll(ringbuf, 200) > 0)
			break;  /* 收到事件后继续轮询一小段时间 */
	}
	/* 排空剩余事件 */
	while (ring_buffer__poll(ringbuf, 100) > 0)
		;

	printf("\nDone.\n");

cleanup:
	ring_buffer__free(ringbuf);
	if (skel)
		iter_memcg_bpf__destroy(skel);
	return err;
}
