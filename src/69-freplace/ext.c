// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 69-freplace: 扩展程序用户态 — 加载 ext + attach 到 target。
 *
 * 用法：sudo ./ext <target_prog_id>
 *
 * 流程：
 *   1. 从 argv 获取 target prog ID
 *   2. bpf_prog_get_fd_by_id 获取 target prog fd
 *   3. open ext skeleton
 *   4. bpf_program__set_attach_target 设置 target fd
 *   5. load ext skeleton
 *   6. bpf_program__attach_freplace attach
 *   7. Ctrl-C → detach → target 恢复原始逻辑
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ext.skel.h"

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
	struct ext_bpf *skel;
	struct bpf_link *link = NULL;
	__u32 target_id, target_fd;
	int err = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <target_prog_id>\n", argv[0]);
		fprintf(stderr, "  run target first to get the prog id\n");
		return 1;
	}

	target_id = atoi(argv[1]);
	if (target_id == 0) {
		fprintf(stderr, "invalid target prog id: %s\n", argv[1]);
		return 1;
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* 1. 通过 prog id 获取 target prog fd */
	target_fd = bpf_prog_get_fd_by_id(target_id);
	if (target_fd < 0) {
		fprintf(stderr, "bpf_prog_get_fd_by_id(%u) failed: %s\n",
			target_id, strerror(errno));
		return 1;
	}
	printf("Got target prog fd=%d (id=%u)\n", target_fd, target_id);

	/* 2. open ext skeleton */
	skel = ext_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open ext skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* 3. 设置 attach target。
	 * 只设置 attach_prog_fd，让 load 时自动解析 BTF ID
	 * （set_attach_target 带 func_name 时不会设置 attach_prog_fd） */
	err = bpf_program__set_attach_target(skel->progs.filter_check,
					     target_fd, NULL);
	if (err) {
		fprintf(stderr, "set_attach_target failed: %s\n", strerror(-err));
		goto cleanup;
	}

	/* 4. load ext skeleton */
	err = ext_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load ext skeleton: %s\n", strerror(-err));
		goto cleanup;
	}

	/* 5. attach freplace */
	link = bpf_program__attach_freplace(skel->progs.filter_check,
					    target_fd, "filter_check");
	if (!link) {
		fprintf(stderr, "attach_freplace failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	printf("freplace attached! filter_check() is now replaced.\n");
	printf("  Only even PIDs will be logged (odd PIDs filtered).\n");
	printf("  Ctrl-C to detach (target restores original logic).\n\n");

	while (!exiting)
		sleep(1);

	printf("\nDetaching freplace...\n");

cleanup:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		ext_bpf__destroy(skel);
	if (target_fd >= 0)
		close(target_fd);
	return err < 0 ? -err : 0;
}
