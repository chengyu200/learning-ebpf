// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 19-lsm-connect: user-space loader.
 *
 * Loads the LSM BPF program and attaches it.  If `bpf` is not in the active LSM
 * list, attach fails with -EOPNOTSUPP; the loader prints guidance instead.
 */
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "lsm-connect.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void read_trace_pipe(void)
{
	char buf[4096];
	int fd;
	ssize_t n;

	fd = open("/sys/kernel/tracing/trace_pipe", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return;
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);
	close(fd);
}

int main(int argc, char **argv)
{
	struct lsm_connect_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = lsm_connect_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = lsm_connect_bpf__attach(skel);
	if (err) {
		fprintf(stderr,
			"Failed to attach LSM program (err=%d).\n"
			"Is `bpf` an active LSM? Check: cat /sys/kernel/security/lsm\n"
			"If not, add `lsm=...,bpf` to the kernel cmdline and reboot.\n",
			err);
		err = 0; /* treat as non-fatal for the demo */
		goto cleanup;
	}

	printf("LSM program attached; blocking connect() to 1.1.1.1.\n");
	printf("Try in another terminal: curl 1.1.1.1  (expect 'Operation not permitted')\n");
	printf("(trace output from /sys/kernel/tracing/trace_pipe follows)\n");

	while (!exiting) {
		read_trace_pipe();
		sleep(1);
	}

cleanup:
	lsm_connect_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
