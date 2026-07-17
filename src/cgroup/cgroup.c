// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* cgroup: user-space loader.  Attaches a cgroup_skb/egress program to the
 * root cgroup (/sys/fs/cgroup) and prints packet/byte counts periodically.
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup.h"
#include "cgroup.skel.h"

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
	struct cgroup_bpf *skel;
	int cgroup_fd, err = 0, ncpu, i;

	if (argc > 1) g_interval = atoi(argv[1]);
	ncpu = sysconf(_SC_NPROCESSORS_ONLN);

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = cgroup_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
	if (cgroup_fd < 0) {
		fprintf(stderr, "open /sys/fs/cgroup: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	link = bpf_program__attach_cgroup(skel->progs.count_egress, cgroup_fd);
	close(cgroup_fd);
	if (!link) {
		fprintf(stderr, "attach cgroup failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	printf("cgroup egress counter on /sys/fs/cgroup... Ctrl-C\n");
	while (!exiting) {
		sleep(g_interval);
		__u32 key = 0;
		struct event *vals = calloc(ncpu, sizeof(struct event));
		__u64 pkts = 0, bytes = 0;
		if (vals && bpf_map__lookup_elem(skel->maps.pkt_stats,
						&key, sizeof(key),
						vals, sizeof(struct event) * ncpu, 0) == 0)
			for (i = 0; i < ncpu; i++) {
				pkts += vals[i].packets;
				bytes += vals[i].bytes;
			}
		free(vals);
		printf("egress: %llu packets, %llu bytes\n", pkts, bytes);
	}

cleanup:
	if (link) bpf_link__destroy(link);
	cgroup_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
