// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 70-fexit-unlink: 用户态 — ringbuf 轮询 + 成功/失败统计。
 *
 * 实时打印每次文件删除的结果（成功/失败 + 错误码），
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
#include "fexit-unlink.h"
#include "fexit-unlink.skel.h"

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

static unsigned long success_cnt, fail_cnt;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	(void)ctx;

	if (e->ret == 0) {
		success_cnt++;
		printf("[SUCCESS] pid=%-6d uid=%-5d comm=%-12s file=%s\n",
		       e->pid, e->uid, e->comm, e->filename);
	} else {
		fail_cnt++;
		printf("[FAILED]  pid=%-6d uid=%-5d comm=%-12s file=%-24s errno=%d (%s)\n",
		       e->pid, e->uid, e->comm, e->filename, -e->ret,
		       strerror(-e->ret));
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct fexit_unlink_bpf *skel;
	int err = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	skel = fexit_unlink_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	err = fexit_unlink_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Tracing vfs_unlink results (fexit). Ctrl-C to stop.\n");
	printf("Test: rm /tmp/test  (success)  |  rm /nonexistent  (fail)\n\n");

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
	printf("  Success: %lu\n", success_cnt);
	printf("  Failed:  %lu\n", fail_cnt);
	printf("  Total:   %lu\n", success_cnt + fail_cnt);

	ring_buffer__free(rb);

cleanup:
	fexit_unlink_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
