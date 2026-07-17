// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 30-sslsniff: user-space loader.  Attaches to libssl SSL_read/SSL_write by
 * function name, prints captured plaintext (truncated).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "sslsniff.h"
#include "sslsniff.skel.h"

static char *g_libssl = "/usr/lib/aarch64-linux-gnu/libssl.so.3";
static pid_t g_pid = 0;
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
	int n = e->data_len > MAX_DATA_SIZE ? MAX_DATA_SIZE : e->data_len;

	time(&t); tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-7d %-6s %s\n", ts, e->pid, e->rw ? "WRITE" : "READ", e->comm);
	printf("         ");
	fwrite(e->data, 1, n, stdout);
	printf("\n");
	return 0;
}

#define ATTACH(prog, sym, is_ret) \
	do { \
		LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = sym, .retprobe = is_ret); \
		struct bpf_link *l = bpf_program__attach_uprobe_opts( \
			skel->progs.prog, g_pid, g_libssl, 0, &uo); \
		if (!l) { fprintf(stderr, "attach " sym " failed: %s\n", strerror(errno)); \
			  err = -errno; goto cleanup; } \
		links[nlinks++] = l; \
	} while (0)

int main(int argc, char **argv)
{
	struct bpf_link *links[4];
	int nlinks = 0, err = 0, i;
	struct ring_buffer *rb = NULL;
	struct sslsniff_bpf *skel;

	if (argc > 1) g_pid = atoi(argv[1]);
	if (argc > 2) g_libssl = argv[2];

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = sslsniff_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	ATTACH(ssl_write_entry, "SSL_write", false);
	ATTACH(ssl_read_entry, "SSL_read", false);
	ATTACH(ssl_read_ret, "SSL_read", true);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	printf("sslsniff on %s (pid=%d)... Ctrl-C\n", g_libssl, g_pid);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

cleanup:
	ring_buffer__free(rb);
	for (i = 0; i < nlinks; i++) bpf_link__destroy(links[i]);
	sslsniff_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
