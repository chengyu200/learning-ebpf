// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 72-ksyscall: 用户态 — ringbuf 轮询 + 事件打印。
 *
 * 实时打印 openat 系统调用的入口参数和返回值 + 延迟。
 * 退出时打印汇总统计。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ksyscall.h"
#include "ksyscall.skel.h"

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

static unsigned long entry_cnt, exit_cnt, success_cnt, fail_cnt;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	(void)ctx;

	if (e->type == EVENT_ENTRY) {
		entry_cnt++;
		printf("[ENTRY] pid=%-6d comm=%-12s openat(\"%s\", flags=0x%x)\n",
		       e->pid, e->comm, e->filename, e->flags);
	} else if (e->type == EVENT_EXIT) {
		exit_cnt++;
		if (e->ret >= 0) {
			success_cnt++;
			printf("[EXIT]  pid=%-6d comm=%-12s openat ret=%d (fd)      latency=%llu ns\n",
			       e->pid, e->comm, e->ret, e->latency_ns);
		} else {
			fail_cnt++;
			printf("[EXIT]  pid=%-6d comm=%-12s openat ret=%d (%s)  latency=%llu ns\n",
			       e->pid, e->comm, e->ret, strerror(-e->ret),
			       e->latency_ns);
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ksyscall_bpf *skel;
	int err = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	skel = ksyscall_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	/* 可选：从 argv[1] 设置 target_pid */
	if (argc > 1)
		skel->rodata->target_pid = atoi(argv[1]);

	err = ksyscall_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("ksyscall: tracing openat (entry + exit). Ctrl-C to stop.\n");
	printf("Test: cat /etc/passwd  (success)  |  cat /nonexistent  (fail)\n\n");

	struct ring_buffer *rb;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && errno != EINTR) {
			fprintf(stderr, "ring_buffer__poll: %s\n", strerror(errno));
			break;
		}
		err = 0;
	}

	printf("\n=== Summary ===\n");
	printf("  Entry events:  %lu\n", entry_cnt);
	printf("  Exit events:   %lu\n", exit_cnt);
	printf("  Success (fd):  %lu\n", success_cnt);
	printf("  Failed:        %lu\n", fail_cnt);

	ring_buffer__free(rb);

cleanup:
	ksyscall_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
