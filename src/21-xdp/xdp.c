// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 21-xdp: user-space loader.
 *
 * Attaches the XDP program in SKB mode to the target interface (default
 * vethbpf0 or lo; override with --dev) and reads trace_pipe for the output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp.skel.h"

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

static int pick_dev(char *name, size_t sz)
{
	const char *cands[] = { "vethbpf0", "lo" };
	size_t i;
	for (i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
		if (if_nametoindex(cands[i])) {
			strncpy(name, cands[i], sz - 1);
			return 0;
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	struct xdp_bpf *skel;
	int ifindex, err, prog_fd;
	char dev[IFNAMSIZ] = {};

	if (argc > 1)
		strncpy(dev, argv[1], sizeof(dev) - 1);
	else if (pick_dev(dev, sizeof(dev)) < 0) {
		fprintf(stderr, "No usable device; pass an interface name.\n");
		return 1;
	}

	ifindex = if_nametoindex(dev);
	if (!ifindex) {
		fprintf(stderr, "Interface %s not found\n", dev);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = xdp_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	prog_fd = bpf_program__fd(skel->progs.xdp_pass);
	/* XDP_FLAGS_SKB_MODE works on lo/veth without driver support. */
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err) {
		fprintf(stderr, "bpf_xdp_attach failed: %s\n", strerror(-err));
		goto cleanup;
	}

	printf("XDP program attached to %s (skb mode). Ctrl-C to stop.\n", dev);
	printf("Generate traffic, e.g.: ping -I %s 10.0.0.2\n", dev);
	while (!exiting) {
		read_trace_pipe();
		sleep(1);
	}

	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

cleanup:
	xdp_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
