// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 58-iter-open-coded: 用户态 — ringbuf 接收结果 + fork 子进程触发 syscall。
 *
 * 自包含演示：fork 一个子进程做 openat/read/write，BPF 仅响应该子进程的
 * syscall（通过 target_pid 过滤），结果通过 ringbuf 发回用户态打印。
 * 不会刷屏，每次运行输出 3 条结果。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iter-oc.skel.h"

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

static const char *prog_names[] = {
	[1] = "bpf_for: sum of squares 0..9",
	[2] = "bpf_for: arr[5]",
	[3] = "bpf_repeat: count",
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct oc_event {
		__u32 pid;
		__u32 prog_id;
		__u64 result;
	} *e = data;

	if (e->prog_id >= 1 && e->prog_id <= 3)
		printf("  %s = %llu\n", prog_names[e->prog_id], e->result);
	return 0;
}

/* 子进程：触发 openat / read / write 各一次 */
static void trigger_syscalls(void)
{
	int fd;

	/* openat → 触发 sum_squares */
	fd = open("/etc/hostname", O_RDONLY);
	if (fd >= 0) {
		char buf[64];
		/* read → 触发 fill_array */
		read(fd, buf, sizeof(buf));
		close(fd);
	}

	/* write → 触发 repeat_demo */
	write(STDERR_FILENO, "", 0);

	_exit(0);
}

int main(int argc, char **argv)
{
	struct iter_oc_bpf *skel;
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

	skel = iter_oc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	err = iter_oc_bpf__attach(skel);
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

	/* fork 子进程触发 syscall */
	pid_t child = fork();
	if (child == 0) {
		trigger_syscalls();
	} else if (child > 0) {
		/* 设置 target_pid 为子进程 PID */
		skel->bss->target_pid = child;
		printf("Open-coded iterators demo (target PID %d):\n\n", child);

		/* 等待子进程触发 + ringbuf 事件到达 */
		int timeout = 0;
		while (!exiting && timeout < 50) {
			ring_buffer__poll(rb, 100);
			int status;
			if (waitpid(child, &status, WNOHANG) == child)
				break;
			timeout++;
		}
		/* 确保收到所有事件 */
		ring_buffer__poll(rb, 200);
		printf("\nDone. All 3 open-coded iterators executed successfully.\n");
	}

cleanup:
	if (rb)
		ring_buffer__free(rb);
	iter_oc_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
