// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 39-nginx: user-space loader.  Attaches to ngx_http_process_request in nginx. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "nginx.h"
#include "nginx.skel.h"

static char *g_nginx = "/usr/sbin/nginx";
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
	printf("%-8s pid=%-7d dur=%.3fms\n", ts, e->pid, e->duration_ns / 1000000.0);
	return 0;
}

#define ATTACH(prog, sym, is_ret) \
	do { \
		LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = sym, .retprobe = is_ret); \
		struct bpf_link *l = bpf_program__attach_uprobe_opts( \
			skel->progs.prog, -1, g_nginx, 0, &uo); \
		if (!l) { fprintf(stderr, "attach " sym " failed: %s\n", strerror(errno)); \
			  err = -errno; goto cleanup; } \
		links[nlinks++] = l; \
	} while (0)

int main(int argc, char **argv)
{
	struct bpf_link *links[2];
	int nlinks = 0, err = 0, i;
	struct ring_buffer *rb = NULL;
	struct nginx_bpf *skel;

	if (argc > 1) g_nginx = argv[1];

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = nginx_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	ATTACH(ngx_process_entry, "ngx_http_process_request", false);
	ATTACH(ngx_process_ret, "ngx_http_process_request", true);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	printf("tracing nginx %s... send HTTP requests. Ctrl-C\n", g_nginx);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

cleanup:
	ring_buffer__free(rb);
	for (i = 0; i < nlinks; i++) bpf_link__destroy(links[i]);
	nginx_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
