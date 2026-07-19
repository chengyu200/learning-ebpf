// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* features/bpf_iters: user-space loader.
 *
 * 创建 bpf_iter link，用 bpf_iter_create 从 link fd 创建可读的 iter fd，
 * 读取所有进程的 pid/comm 列表。
 *
 * 教学概念：
 * - bpf_iter 程序类型：遍历内核数据结构（如 task），通过 seq_file 输出
 * - bpf_program__attach_iter：创建 iter link
 * - bpf_iter_create：从 link fd 创建可读的 iter fd（不能直接 read link fd）
 * - BPF_SEQ_PRINTF：内核侧用 seq_file 格式输出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iters.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct iters_bpf *skel;
	int err = 0, iter_fd;
	char buf[256];
	ssize_t n;

	libbpf_set_print(libbpf_print_fn);
	setvbuf(stdout, NULL, _IONBF, 0);

	skel = iters_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	/* 创建 bpf_iter link */
	link = bpf_program__attach_iter(skel->progs.dump_task, NULL);
	if (!link) {
		fprintf(stderr, "attach_iter failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* bpf_iter link fd 不能直接 read()。
	 * 需要用 bpf_iter_create 创建一个可读的 iter fd。 */
	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "bpf_iter_create failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 读取 iter fd：内核会执行 BPF 程序遍历所有 task，
	 * 输出通过 seq_file 格式写入。 */
	while ((n = read(iter_fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);

	close(iter_fd);

cleanup:
	if (link) bpf_link__destroy(link);
	iters_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
