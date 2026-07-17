// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 28-detach: user-space loader.  Demonstrates eBPF program lifecycle.
 *
 *   ./detach attach    — load + pin link, exit (program keeps running)
 *   ./detach status    — read the pinned counter map
 *   ./detach clean     — destroy the pinned link + unload
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "detach.skel.h"

#define PIN_LINK  "/sys/fs/bpf/detach_exec_count_link"
#define PIN_MAP   "/sys/fs/bpf/detach_exec_count_map"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	const char *cmd = (argc > 1) ? argv[1] : "attach";

	libbpf_set_print(libbpf_print_fn);

	if (!strcmp(cmd, "attach")) {
		struct detach_bpf *skel = detach_bpf__open_and_load();
		if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }
		int err = detach_bpf__attach(skel);
		if (err) { fprintf(stderr, "attach failed\n"); return 1; }

		if (bpf_link__pin(skel->links.count_exec, PIN_LINK)) {
			fprintf(stderr, "pin link failed: %s\n", strerror(errno));
			return 1;
		}
		if (bpf_map__pin(skel->maps.exec_count, PIN_MAP)) {
			fprintf(stderr, "pin map failed: %s\n", strerror(errno));
			return 1;
		}
		printf("pinned. exiting (program keeps running).\n");
		/* Do NOT destroy: the pinned link/map keep it alive. */
		skel->links.count_exec = NULL;
		skel->maps.exec_count = NULL;
		detach_bpf__destroy(skel);
		return 0;
	}

	if (!strcmp(cmd, "status")) {
		int map_fd = bpf_obj_get(PIN_MAP);
		if (map_fd < 0) { fprintf(stderr, "map not pinned\n"); return 1; }
		__u32 key = 0; __u64 val = 0;
		if (bpf_map_lookup_elem(map_fd, &key, &val)) {
			fprintf(stderr, "lookup failed\n"); return 1;
		}
		printf("execve count: %llu\n", val);
		return 0;
	}

	if (!strcmp(cmd, "clean")) {
		int link_fd = bpf_obj_get(PIN_LINK);
		if (link_fd >= 0) {
			struct bpf_link *l = bpf_link__open(PIN_LINK);
			if (l) bpf_link__destroy(l);
		}
		unlink(PIN_LINK);
		unlink(PIN_MAP);
		printf("cleaned.\n");
		return 0;
	}

	fprintf(stderr, "usage: %s [attach|status|clean]\n", argv[0]);
	return 1;
}
