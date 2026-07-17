// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* features/bpf_iters: user-space loader.  Creates a bpf_iter link and reads
 * the iterator output (all tasks) by reading the link's fd.
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
	int err = 0, link_fd;
	char buf[256];
	ssize_t n;

	libbpf_set_print(libbpf_print_fn);

	skel = iters_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	link = bpf_program__attach_iter(skel->progs.dump_task, NULL);
	if (!link) { fprintf(stderr, "attach_iter failed: %s\n", strerror(errno));
		     err = -errno; goto cleanup; }

	link_fd = bpf_link__fd(link);
	/* Read the iterator output.  On newer kernels, reading the link fd
	 * produces the seq output.  Alternatively pin and cat /proc/bpf/iter. */
	while ((n = read(link_fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);

cleanup:
	if (link) bpf_link__destroy(link);
	iters_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
