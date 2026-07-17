// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 37-uprobe-rust: user-space loader.  Attaches to slow_function in the Rust
 * target binary (default ./target), prints each call.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "uprobe-rust.h"
#include "uprobe-rust.skel.h"

static char *g_target = "./target";
static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm; char ts[32]; time_t t;
	time(&t); tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s pid=%-7d arg=%llu\n", ts, e->pid, e->arg);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct ring_buffer *rb = NULL;
	struct uprobe_rust_bpf *skel;
	int err = 0;

	if (argc > 1) g_target = argv[1];

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = uprobe_rust_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	/* Use offset 0 (let libbpf find by func_name); if that fails the user
	 * can pass an explicit offset.  Here we try func_name first. */
	LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = "slow_function");
	link = bpf_program__attach_uprobe_opts(skel->progs.trace_slow_function,
					       0 /* any pid */, g_target, 0, &uo);
	if (!link) {
		/* Fallback: attach by offset 0x8838 (slow_function in target.rs).
		 * Recompute with `nm target | grep slow_function` for other builds. */
		fprintf(stderr, "func_name lookup failed, trying offset 0x8838\n");
		link = bpf_program__attach_uprobe(skel->progs.trace_slow_function,
						  false, 0, g_target, 0x8838);
	}
	if (!link) { fprintf(stderr, "attach slow_function in %s: %s\n",
			     g_target, strerror(errno)); err = -errno; goto cleanup; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	printf("tracing slow_function in %s... Ctrl-C\n", g_target);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

cleanup:
	ring_buffer__free(rb);
	if (link) bpf_link__destroy(link);
	uprobe_rust_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
