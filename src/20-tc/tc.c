// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 20-tc: user-space loader.
 *
 * Creates a clsact qdisc on the target interface and attaches the tc BPF
 * program to its ingress hook.  Defaults to vethbpf0 (see scripts/setup-veth.sh)
 * or lo; override with --dev.  Reads trace_pipe for the BPF output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tc.skel.h"

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
	struct tc_bpf *skel;
	int ifindex, err;
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

	skel = tc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Create clsact qdisc and attach to ingress.  LIBBPF_OPTS sets the
	 * required .sz field of these structs.  Destroy any stale clsact left by
	 * a previously killed run first, so attach always starts clean. */
	LIBBPF_OPTS(bpf_tc_hook, h, .ifindex = ifindex,
		    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	bpf_tc_hook_destroy(&h);
	h.attach_point = BPF_TC_INGRESS;
	err = bpf_tc_hook_create(&h);
	if (err && err != -EEXIST) {
		fprintf(stderr, "bpf_tc_hook_create failed: %s\n", strerror(-err));
		goto cleanup;
	}

	LIBBPF_OPTS(bpf_tc_opts, o, .handle = 1, .priority = 1,
		    .prog_fd = bpf_program__fd(skel->progs.tc_ingress), .flags = 0);
	err = bpf_tc_attach(&h, &o);
	if (err) {
		fprintf(stderr, "bpf_tc_attach failed: %s\n", strerror(-err));
		h.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		bpf_tc_hook_destroy(&h);
		goto cleanup;
	}

	printf("tc ingress program attached to %s. Ctrl-C to stop.\n", dev);
	printf("Generate traffic, e.g.: ping -I %s 10.0.0.2\n", dev);
	while (!exiting) {
		read_trace_pipe();
		sleep(1);
	}

	/* Detach + remove qdisc. */
	h.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
	bpf_tc_hook_destroy(&h);

cleanup:
	tc_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
