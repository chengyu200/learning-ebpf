// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 69-freplace: 目标程序用户态 — 加载 target + ringbuf 轮询。
 *
 * 加载后打印所有 exec 事件。
 * 当 ext 程序 attach 后，filtered=1 的事件增多（PID 为奇数 被过滤）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "freplace.h"
#include "target.skel.h"

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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct exec_event *e = data;
	(void)ctx;

	if (e->filtered)
		printf("[FILTERED] pid=%-6d comm=%s\n", e->pid, e->comm);
	else
		printf("[EXEC]     pid=%-6d comm=%s\n", e->pid, e->comm);
	return 0;
}

int main(int argc, char **argv)
{
	struct target_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	skel = target_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load target skeleton\n");
		return 1;
	}

	err = target_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		goto cleanup;
	}

	/* 打印 prog id，供 ext 程序使用 */
	int prog_fd = bpf_program__fd(skel->progs.target_prog);
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	printf("Target program loaded.\n");
	printf("  prog_id=%u (use with: sudo ./ext %u)\n\n", info.id, info.id);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		err = 1;
		goto cleanup;
	}

	printf("Tracing exec events. Run 'sudo ./ext %u' to replace filter_check.\n", info.id);
	printf("Ctrl-C to stop.\n\n");

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && errno != EINTR) {
			fprintf(stderr, "ring_buffer__poll: %s\n", strerror(errno));
			break;
		}
		err = 0;
	}

cleanup:
	if (rb)
		ring_buffer__free(rb);
	target_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
