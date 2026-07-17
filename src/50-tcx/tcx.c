// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 50-tcx: user-space loader. Attaches via bpf_program__attach_tcx and prints
 * per-CPU IPv4 packet counts periodically.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcx.skel.h"

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
	struct bpf_link *link = NULL;
	struct tcx_bpf *skel;
	int ifindex, err, ncpu, i;

	if (argc > 1) g_ifname = argv[1];
	if (argc > 2) g_interval = atoi(argv[2]);
	ifindex = if_nametoindex(g_ifname);
	if (!ifindex) { fprintf(stderr, "if %s not found\n", g_ifname); return 1; }
	ncpu = sysconf(_SC_NPROCESSORS_ONLN);

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = tcx_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	LIBBPF_OPTS(bpf_tcx_opts, opts);
	link = bpf_program__attach_tcx(skel->progs.tcx_count, ifindex, &opts);
	if (!link) {
		fprintf(stderr, "tcx attach failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	printf("tcx on %s; generate traffic. Ctrl-C\n", g_ifname);
	while (!exiting) {
		sleep(g_interval);
		__u64 total = 0;
		__u64 *vals = calloc(ncpu, sizeof(__u64));
		__u32 key = 0;
		if (vals && bpf_map_lookup_elem(bpf_map__fd(skel->maps.ip_pkts),
						&key, vals) == 0)
			for (i = 0; i < ncpu; i++)
				total += vals[i];
		free(vals);
		printf("ipv4 packets: %llu\n", total);
	}

cleanup:
	if (link) bpf_link__destroy(link);
	tcx_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
