// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 35-user-ringbuf: user-space loader.
 *
 * 用 libbpf 的 user_ring_buffer API 向内核异步发送消息。
 * 内核侧的 perf_event 程序用 bpf_user_ringbuf_drain 排空消息并打印。
 *
 * 教学概念：
 * - BPF_MAP_TYPE_USER_RINGBUF：用户态→内核态的环形缓冲区
 * - user_ring_buffer__new/reserve/submit：libbpf 用户态 API
 * - bpf_user_ringbuf_drain：内核侧排空 helper
 * - perf_event 程序作为定期触发器
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "user-ringbuf.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct user_ringbuf_bpf *skel;
	struct user_ring_buffer *urb = NULL;
	int err = 0, i, ncpu;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = user_ringbuf_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }
	err = user_ringbuf_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach failed\n"); goto cleanup; }

	/* 用 perf_event (CPU_CLOCK, 5Hz) 定期触发 BPF 程序排空 user ringbuf */
	struct perf_event_attr attr = {
		.size = sizeof(attr),
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
		.sample_type = PERF_SAMPLE_RAW,
		.freq = 1, .sample_freq = 5, .disabled = 1,
	};

	ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	for (i = 0; i < ncpu; i++) {
		int fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) continue;
		struct bpf_link *l = bpf_program__attach_perf_event(
			skel->progs.drain_user_ring, fd);
		if (l && i == 0) { link = l; }
		else if (l) bpf_link__destroy(l);
		else close(fd);
	}

	/* 创建 user ring buffer 实例（libbpf 封装了 mmap + 原子操作） */
	urb = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ring), NULL);
	if (!urb) {
		fprintf(stderr, "user_ring_buffer__new failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("user-ringbuf demo: writing messages... Ctrl-C\n");
	printf("(watch trace_pipe for kernel-side drain output)\n");

	int seq = 0;
	while (!exiting) {
		char msg[32];
		int n = snprintf(msg, sizeof(msg), "hello %d", seq++);

		/* 在 user ringbuf 中预留空间，写入数据，然后提交 */
		void *slot = user_ring_buffer__reserve(urb, n + 1);
		if (slot) {
			memcpy(slot, msg, n + 1);
			user_ring_buffer__submit(urb, slot);
			printf("wrote: %s\n", msg);
		}
		sleep(1);
	}

cleanup:
	if (link) bpf_link__destroy(link);
	user_ring_buffer__free(urb);
	user_ringbuf_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
