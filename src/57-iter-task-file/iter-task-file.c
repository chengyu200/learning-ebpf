// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 57-iter-task-file: 用户态 — 加载 iter/task_file 程序，参数化遍历进程文件。
 *
 * 用法：
 *   sudo ./iter-task-file              # 遍历所有进程的所有打开文件
 *   sudo ./iter-task-file --pid 1234    # 仅遍历 PID=1234 的进程
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iter-task-file.skel.h"

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

int main(int argc, char **argv)
{
	struct iter_task_file_bpf *skel;
	struct bpf_link *link = NULL;
	struct bpf_iter_attach_opts opts;
	union bpf_iter_link_info linfo;
	int err = 0, iter_fd;
	pid_t target_pid = 0;
	char buf[256];
	ssize_t n;

	/* 解析 --pid 参数 */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
			target_pid = atoi(argv[++i]);
		}
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	skel = iter_task_file_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	/* 设置全局变量过滤（另一种过滤方式，与 attach_opts 互补） */
	skel->bss->target_pid = (target_pid > 0) ? target_pid : 0;

	/* 参数化 attach：用 attach_opts 在内核侧过滤（更高效） */
	memset(&linfo, 0, sizeof(linfo));
	memset(&opts, 0, sizeof(opts));
	opts.sz = sizeof(opts);
	if (target_pid > 0) {
		linfo.task.pid = target_pid;
		opts.link_info = &linfo;
		opts.link_info_len = sizeof(linfo);
	}

	link = bpf_program__attach_iter(skel->progs.dump_task_file, &opts);
	if (!link) {
		fprintf(stderr, "attach_iter failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "bpf_iter_create failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	if (target_pid > 0)
		printf("=== Files opened by PID %d ===\n", target_pid);
	else
		printf("=== All opened files (system-wide) ===\n");

	while (!exiting && (n = read(iter_fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);

	close(iter_fd);

cleanup:
	if (link)
		bpf_link__destroy(link);
	iter_task_file_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
