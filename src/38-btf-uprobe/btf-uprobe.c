// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 38-btf-uprobe: user-space loader.  Attaches to malloc in libc. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "btf-uprobe.skel.h"

static char *g_libc = "/usr/lib/aarch64-linux-gnu/libc.so.6";
static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct { __u32 pid; __u64 size; } *e = data;
	printf("pid=%d malloc(%llu)\n", e->pid, e->size);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct ring_buffer *rb = NULL;
	struct btf_uprobe_bpf *skel;
	int err = 0;

	if (argc > 1) g_libc = argv[1];
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = btf_uprobe_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = "malloc");
	link = bpf_program__attach_uprobe_opts(skel->progs.trace_malloc,
					       0, g_libc, 0, &uo);
	if (!link) { fprintf(stderr, "attach malloc: %s\n", strerror(errno));
		     err = -errno; goto cleanup; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	printf("tracing malloc in %s... Ctrl-C\n", g_libc);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

cleanup:
	ring_buffer__free(rb);
	if (link) bpf_link__destroy(link);
	btf_uprobe_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
