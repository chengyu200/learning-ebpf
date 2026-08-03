// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 60-iter-bpf-map: 用户态 — 遍历系统中所有 BPF map。
 *
 * 类似 bpftool map show，但用 BPF iterator 实现。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iter-bpf-map.skel.h"

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
	struct iter_bpf_map_bpf *skel;
	struct bpf_link *link = NULL;
	int err = 0, iter_fd;
	char buf[256];
	ssize_t n;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	skel = iter_bpf_map_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	link = bpf_program__attach_iter(skel->progs.dump_bpf_map, NULL);
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

	printf("=== All BPF Maps ===\n");

	while (!exiting && (n = read(iter_fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);

	close(iter_fd);

cleanup:
	if (link)
		bpf_link__destroy(link);
	iter_bpf_map_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
