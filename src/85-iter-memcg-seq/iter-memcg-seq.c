// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 85-iter-memcg-seq: 用户态 — 遍历 cgroup 层级并输出 mem_cgroup 信息。
 *
 * iter/cgroup 需要 bpf_iter_attach_opts 指定遍历顺序和起始 cgroup。
 *   --order pre|post|self|ancestors  (默认 pre，前序遍历后代)
 *   --cgroup /sys/fs/cgroup           (默认根 cgroup)
 *
 * 用法：
 *   sudo ./iter-memcg-seq
 *   sudo ./iter-memcg-seq --cgroup /sys/fs/cgroup/system.slice
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iter-memcg-seq.skel.h"

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
	struct iter_memcg_seq_bpf *skel;
	struct bpf_link *link = NULL;
	struct bpf_iter_attach_opts opts;
	union bpf_iter_link_info linfo;
	int err = 0, iter_fd, cg_fd = -1;
	const char *cg_path = "/sys/fs/cgroup";
	const char *order_str = "pre";
	int order = 2;  /* BPF_CGROUP_ITER_DESCENDANTS_PRE */
	char buf[65536];
	ssize_t n;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--cgroup") == 0 && i + 1 < argc)
			cg_path = argv[++i];
		else if (strcmp(argv[i], "--order") == 0 && i + 1 < argc) {
			order_str = argv[++i];
			if (strcmp(order_str, "self") == 0) order = 1;
			else if (strcmp(order_str, "pre") == 0) order = 2;
			else if (strcmp(order_str, "post") == 0) order = 3;
			else if (strcmp(order_str, "ancestors") == 0) order = 4;
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

	skel = iter_memcg_seq_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	/* 打开 cgroup 目录作为 fd */
	cg_fd = open(cg_path, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "open %s: %s\n", cg_path, strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 设置 attach_opts：order + cgroup_fd */
	memset(&linfo, 0, sizeof(linfo));
	linfo.cgroup.order = order;
	linfo.cgroup.cgroup_fd = cg_fd;

	memset(&opts, 0, sizeof(opts));
	opts.sz = sizeof(opts);
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.dump_memcg, &opts);
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

	printf("=== Mem Cgroup Hierarchy (root=%s, order=%s) ===\n\n", cg_path, order_str);

	while (!exiting && (n = read(iter_fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);

	close(iter_fd);

cleanup:
	if (cg_fd >= 0)
		close(cg_fd);
	if (link)
		bpf_link__destroy(link);
	iter_memcg_seq_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
