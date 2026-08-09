// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 74-uprobe-multi-session: 用户态加载器。
 *
 * 本程序是自包含的：目标函数 work_a/work_b/work_c 定义在本文件中，
 * BPF 程序 attach 到本进程自身 (pid=0)，无需外部二进制。
 *
 * 流程：
 *   1. 定义目标函数 work_a, work_b, work_c（noinline 防止内联）
 *   2. 获取自身二进制路径 (/proc/self/exe)
 *   3. 加载 BPF skeleton
 *   4. 手动 attach 三个程序：
 *      - uprobe.multi  → work_a + work_b（入口，cookie=FUNC_A/FUNC_B）
 *      - uretprobe.multi → work_a + work_b（返回，cookie 同上）
 *      - uprobe.session → work_c（入口+返回，session cookie）
 *   5. 循环调用目标函数，触发 BPF 事件
 *   6. ringbuf 轮询打印事件
 *   7. Ctrl-C 清理
 *
 * 编译：make -C src/74-uprobe-multi-session
 * 运行：sudo ./src/74-uprobe-multi-session/uprobe-multi-session
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "uprobe-multi-session.h"
#include "uprobe-multi-session.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* ── 目标函数（必须 noinline，否则编译器内联后无符号可 attach） ──
 *
 * work_a / work_b: 被 uprobe.multi + uretprobe.multi attach
 * work_c:          被 uprobe.session attach
 *
 * 每个函数有不同的延迟，方便观察 session 延迟测量
 */
__attribute__((noinline))
static int work_a(int n)
{
	volatile int x = n;
	usleep(1000);  /* ~1ms */
	return x + 1;
}

__attribute__((noinline))
static int work_b(int n)
{
	volatile int x = n;
	usleep(2000);  /* ~2ms */
	return x + 2;
}

__attribute__((noinline))
static int work_c(int n)
{
	volatile int x = n;
	usleep(3000);  /* ~3ms */
	return x + 3;
}

/* 获取自身二进制路径 */
static int get_self_path(char *buf, size_t sz)
{
	ssize_t n = readlink("/proc/self/exe", buf, sz - 1);
	if (n < 0)
		return -errno;
	buf[n] = '\0';
	return 0;
}

static const char *event_type_str(__u32 type)
{
	switch (type) {
	case EVENT_ENTRY:   return "ENTRY  ";
	case EVENT_RETURN:  return "RETURN ";
	case EVENT_SESSION: return "SESSION";
	default:            return "UNKNOWN";
	}
}

static const char *func_name_str(__u32 func_id)
{
	switch (func_id) {
	case FUNC_A: return "work_a";
	case FUNC_B: return "work_b";
	default:     return "-";
	}
}

/* ringbuf 回调：打印事件 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;

	if (e->type == EVENT_SESSION) {
		printf("[%s] func=work_c  latency=%llu us  pid=%u\n",
		       event_type_str(e->type),
		       e->latency_ns / 1000, e->pid);
	} else if (e->type == EVENT_ENTRY) {
		printf("[%s] func=%-5s arg=%u  pid=%u\n",
		       event_type_str(e->type),
		       func_name_str(e->func_id),
		       e->arg, e->pid);
	} else {
		printf("[%s] func=%-5s  pid=%u\n",
		       event_type_str(e->type),
		       func_name_str(e->func_id),
		       e->pid);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct uprobe_multi_session_bpf *skel;
	struct bpf_link *entry_link = NULL, *return_link = NULL, *session_link = NULL;
	struct ring_buffer *ringbuf = NULL;
	char self_path[PATH_MAX];
	int err = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	/* 1. 获取自身路径 */
	err = get_self_path(self_path, sizeof(self_path));
	if (err) {
		fprintf(stderr, "Failed to get self path: %s\n", strerror(-err));
		return 1;
	}

	/* 2. 加载 skeleton */
	skel = uprobe_multi_session_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load skeleton\n");
		return 1;
	}

	/* 3. 手动 attach uprobe.multi — work_a + work_b 入口 */
	const char *entry_syms[] = { "work_a", "work_b" };
	__u64 entry_cookies[] = { FUNC_A, FUNC_B };
	LIBBPF_OPTS(bpf_uprobe_multi_opts, entry_opts,
		.syms    = entry_syms,
		.cookies = entry_cookies,
		.cnt     = 2,
		.session = false,
		.retprobe = false,
	);

	entry_link = bpf_program__attach_uprobe_multi(
		skel->progs.uprobe_multi_entry, 0, self_path, NULL, &entry_opts);
	if (!entry_link) {
		fprintf(stderr, "attach uprobe.multi failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 4. 手动 attach uretprobe.multi — work_a + work_b 返回 */
	const char *ret_syms[] = { "work_a", "work_b" };
	__u64 ret_cookies[] = { FUNC_A, FUNC_B };
	LIBBPF_OPTS(bpf_uprobe_multi_opts, ret_opts,
		.syms     = ret_syms,
		.cookies  = ret_cookies,
		.cnt      = 2,
		.session  = false,
		.retprobe = true,
	);

	return_link = bpf_program__attach_uprobe_multi(
		skel->progs.uprobe_multi_return, 0, self_path, NULL, &ret_opts);
	if (!return_link) {
		fprintf(stderr, "attach uretprobe.multi failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 5. 手动 attach uprobe.session — work_c 入口+返回 */
	const char *session_syms[] = { "work_c" };
	LIBBPF_OPTS(bpf_uprobe_multi_opts, session_opts,
		.syms     = session_syms,
		.cnt      = 1,
		.session  = true,
		.retprobe = false,
	);

	session_link = bpf_program__attach_uprobe_multi(
		skel->progs.uprobe_session_prog, 0, self_path, NULL, &session_opts);
	if (!session_link) {
		fprintf(stderr, "attach uprobe.session failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 6. 设置 ringbuf */
	int rb_fd = bpf_map__fd(skel->maps.rb);
	ringbuf = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	printf("Attached:\n");
	printf("  uprobe.multi    → work_a, work_b (entry,  with cookies)\n");
	printf("  uretprobe.multi → work_a, work_b (return,with cookies)\n");
	printf("  uprobe.session  → work_c (entry + return)\n");
	printf("\nCalling work_a/work_b/work_c 5 times...\n\n");

	/* 7. 调用目标函数触发 BPF 事件 */
	for (int i = 0; i < 5 && !exiting; i++) {
		work_a(i);
		work_b(i);
		work_c(i);
		ring_buffer__poll(ringbuf, 100);
	}

	/* 排空 ringbuf 中剩余事件 */
	while (ring_buffer__poll(ringbuf, 100) > 0)
		;

	printf("\nDone. Press Ctrl-C to exit.\n");
	while (!exiting)
		sleep(1);

cleanup:
	ring_buffer__free(ringbuf);
	if (session_link)
		bpf_link__destroy(session_link);
	if (return_link)
		bpf_link__destroy(return_link);
	if (entry_link)
		bpf_link__destroy(entry_link);
	if (skel)
		uprobe_multi_session_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
