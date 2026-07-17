// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 31-goroutine: user-space loader.  Attaches uprobe to runtime.newproc in a Go
 * binary (default ./gotest; pass path as argv[1]).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "goroutine.skel.h"

static char *g_target = "./gotest";
static volatile sig_atomic_t exiting;
static int g_count;

static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	g_count++;
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct ring_buffer *rb = NULL;
	struct goroutine_bpf *skel;
	int err = 0;

	if (argc > 1) g_target = argv[1];

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = goroutine_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = "runtime.newproc");
	link = bpf_program__attach_uprobe_opts(skel->progs.trace_newproc,
					       0, g_target, 0, &uo);
	if (!link) {
		fprintf(stderr, "attach runtime.newproc in %s: %s\n",
			g_target, strerror(errno));
		err = -errno;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	printf("tracing goroutine creation in %s... Ctrl-C\n", g_target);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}
	printf("\ntotal goroutine creations: %d\n", g_count);

cleanup:
	ring_buffer__free(rb);
	if (link) bpf_link__destroy(link);
	goroutine_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
