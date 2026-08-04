// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 63-tp-btf: 用户态 — attach tp_btf 程序 + ringbuf 轮询。
 *
 * tp_btf 程序通过 skeleton 自动 attach（libbpf 解析 BTF ID）。
 * 用户态只需 ring_buffer__poll 接收事件并打印。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tp-btf.h"
#include "tp-btf.skel.h"

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
	const struct event *e = data;
	(void)ctx;

	switch (e->type) {
	case EVENT_EXEC:
		printf("[EXEC] pid=%d ppid=%d comm=%s filename=%s\n",
		       e->pid, e->ppid, e->comm, e->filename);
		break;
	case EVENT_FORK:
		printf("[FORK] pid=%d ppid=%d comm=%s\n",
		       e->pid, e->ppid, e->comm);
		break;
	case EVENT_EXIT:
		printf("[EXIT] pid=%d ppid=%d comm=%s exit_code=%d\n",
		       e->pid, e->ppid, e->comm, e->exit_code);
		break;
	default:
		printf("[????] unknown event type %d\n", e->type);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct tp_btf_bpf *skel;
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

	skel = tp_btf_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	err = tp_btf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		err = 1;
		goto cleanup;
	}

	printf("tp-btf: tracing process lifecycle (tp_btf). Ctrl-C to stop.\n\n");

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && errno != EINTR) {
			fprintf(stderr, "ring_buffer__poll: %s\n", strerror(errno));
			break;
		}
		/* reset err to 0 so we don't return negative */
		err = 0;
	}

cleanup:
	if (rb)
		ring_buffer__free(rb);
	tp_btf_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
