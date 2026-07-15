// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 1-helloworld: user-space loader.
 *
 * Loads the eBPF program, attaches it, and copies the kernel trace pipe to
 * stdout so you can see the "Hello eBPF!" messages produced by every execve().
 */
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "helloworld.skel.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/* Copy whatever the kernel wrote to the trace pipe to stdout. */
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
	struct helloworld_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = helloworld_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = helloworld_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Hello eBPF! Running... press Ctrl-C to stop.\n");
	printf("You can also run in another terminal: sudo cat /sys/kernel/tracing/trace_pipe\n");
	printf("%-8s %-6s %s\n", "PID", "COMM", "(raw trace_printk output follows)");
	printf("------------------------------------------------------------\n");

	while (!exiting) {
		read_trace_pipe();
		sleep(1);
	}

cleanup:
	helloworld_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
