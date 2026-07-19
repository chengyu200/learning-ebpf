// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 43-kfuncs: user-space loader.  Requires the bpf_kfunc_demo.ko module loaded.
 *   cd src/43-kfuncs/kernel && make && sudo insmod bpf_kfunc_demo.ko
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "kfuncs.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct { __u32 pid; char msg[64]; } *e = data;
	printf("pid=%d kfunc=%s\n", e->pid, e->msg);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct kfuncs_bpf *skel;
	int err = 0;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGTERM, sig_handler);

	skel = kfuncs_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "open/load failed (is bpf_kfunc_demo.ko loaded?)\n");
		return 1;
	}
	err = kfuncs_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach failed\n"); goto cleanup; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	printf("kfuncs demo running... Ctrl-C\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

cleanup:
	ring_buffer__free(rb);
	kfuncs_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
