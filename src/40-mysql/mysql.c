// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 40-mysql: user-space loader.  Attaches to dispatch_command in mysqld.
 * Compile-only on hosts without mysqld (README documents the runtime steps).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "mysql.skel.h"

static char *g_mysqld = "/usr/sbin/mysqld";
static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct { __u32 pid; __u64 ts_ns; __u16 query_len; char query[256]; } *e = data;
	struct tm *tm; char ts[32]; time_t t;
	time(&t); tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s pid=%-7d QUERY: %s\n", ts, e->pid, e->query);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct ring_buffer *rb = NULL;
	struct mysql_bpf *skel;
	int err = 0;

	if (argc > 1) g_mysqld = argv[1];

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = mysql_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = "dispatch_command");
	link = bpf_program__attach_uprobe_opts(skel->progs.mysql_dispatch,
					      0, g_mysqld, 0, &uo);
	if (!link) {
		fprintf(stderr, "attach dispatch_command in %s: %s\n",
			g_mysqld, strerror(errno));
		fprintf(stderr, "(This example needs mysqld with debug symbols.)\n");
		err = -errno;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	printf("tracing MySQL queries in %s... Ctrl-C\n", g_mysqld);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

cleanup:
	ring_buffer__free(rb);
	if (link) bpf_link__destroy(link);
	mysql_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
