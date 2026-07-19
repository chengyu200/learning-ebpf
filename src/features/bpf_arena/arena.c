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
{ return vfprintf(stderr, format, args); }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const __u64 *val = data;
	printf("arena counter: %llu\n", *val);
	return 0;
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

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("arena demo: run commands to trigger... Ctrl-C\n");

	struct ring_buffer *rb = ring_buffer__new(
		bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}
	ring_buffer__free(rb);
cleanup:
	arena_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
