// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 46-xdp-test: user-space loader.  Prints per-CPU packet counts periodically. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp-test.skel.h"

static char *g_ifname = "vethbpf0";
static int g_interval = 2;
static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct xdp_test_bpf *skel;
	int ifindex, err, prog_fd, ncpu, i;
	__u64 total, val;
	__u32 key = 0;

	if (argc > 1) g_ifname = argv[1];
	if (argc > 2) g_interval = atoi(argv[2]);
	ifindex = if_nametoindex(g_ifname);
	if (!ifindex) { fprintf(stderr, "if %s not found\n", g_ifname); return 1; }
	ncpu = sysconf(_SC_NPROCESSORS_ONLN);

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = xdp_test_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	prog_fd = bpf_program__fd(skel->progs.xdp_gen);
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err) { fprintf(stderr, "xdp attach: %s\n", strerror(-err)); goto cleanup; }

	printf("xdp-test on %s; generate traffic and watch counts. Ctrl-C\n", g_ifname);
	while (!exiting) {
		sleep(g_interval);
		total = 0;
		__u64 *vals = calloc(ncpu, sizeof(__u64));
		if (vals && bpf_map_lookup_elem(bpf_map__fd(skel->maps.pkt_count),
						&key, vals) == 0)
			for (i = 0; i < ncpu; i++)
				total += vals[i];
		free(vals);
		printf("packets: %llu\n", total);
	}
	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

cleanup:
	xdp_test_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
