// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* features/bpf_arena: user-space loader. */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "arena.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct arena_bpf *skel;
	int err = 0;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = arena_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }
	err = arena_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach failed\n"); goto cleanup; }

	printf("bpf_arena demo; run commands to trigger execve... Ctrl-C\n");
	while (!exiting) sleep(1);

	__u32 key = 0; __u64 val = 0;
	bpf_map__lookup_elem(skel->maps.arena, &key, sizeof(key), &val, sizeof(val), 0);
	printf("arena[0] = %llu\n", val);

cleanup:
	arena_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
