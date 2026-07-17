// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 40-mysql: user-space loader.
 *
 * Attaches uprobe to dispatch_command in mysqld/mariadbd.
 * Automatically detects the binary path and resolves the (possibly C++
 * mangled) symbol name via nm.  Falls back to offset-based attach.
 *
 * Usage: ./mysql [path/to/mysqld]
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

static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

/* event struct must match BPF side */
struct event {
	__u32 pid;
	__u64 ts_ns;
	char query[256];
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm; char ts[32]; time_t t;
	time(&t); tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s pid=%-7d QUERY: %s\n", ts, e->pid, e->query);
	return 0;
}

/* Find the mysqld/mariadbd binary path. */
static const char *find_mysqld(void)
{
	const char *cands[] = { "/usr/sbin/mariadbd", "/usr/sbin/mysqld", NULL };
	int i;
	for (i = 0; cands[i]; i++)
		if (access(cands[i], F_OK) == 0)
			return cands[i];
	return NULL;
}

/* Use nm to find the (possibly mangled) symbol for dispatch_command.
 * Returns the offset (hex string) or NULL. */
static int find_symbol_offset(const char *binary, const char *sym_prefix,
			      unsigned long *out_offset)
{
	char cmd[512];
	FILE *fp;

	snprintf(cmd, sizeof(cmd), "nm -D %s 2>/dev/null", binary);
	fp = popen(cmd, "r");
	if (!fp) return -1;

	char line[512];
	while (fgets(line, sizeof(line), fp)) {
		/* nm format: "00000000007f37c8 T _Z16dispatch_command..." */
		if (strstr(line, sym_prefix)) {
			char *p = line;
			*out_offset = strtoul(p, &p, 16);
			pclose(fp);
			return 0;
		}
	}
	pclose(fp);
	return -1;
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct ring_buffer *rb = NULL;
	struct mysql_bpf *skel;
	int err = 0;
	const char *binary;
	unsigned long offset = 0;

	binary = (argc > 1) ? argv[1] : find_mysqld();
	if (!binary) {
		fprintf(stderr, "No mysqld/mariadbd found. Pass path as argument.\n");
		return 1;
	}
	printf("target binary: %s\n", binary);

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = mysql_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	/* Try func_name first (works for non-mangled symbols). */
	LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = "dispatch_command");
	link = bpf_program__attach_uprobe_opts(skel->progs.mysql_dispatch,
					       -1, binary, 0, &uo);

	/* If func_name fails (C++ mangled), resolve offset via nm. */
	if (!link) {
		if (find_symbol_offset(binary, "dispatch_command", &offset) == 0) {
			fprintf(stderr, "trying offset 0x%lx (mangled symbol)\n", offset);
			LIBBPF_OPTS(bpf_uprobe_opts, uo2);
			link = bpf_program__attach_uprobe_opts(skel->progs.mysql_dispatch,
							       -1, binary, offset, &uo2);
		}
	}

	if (!link) {
		fprintf(stderr, "attach dispatch_command in %s failed: %s\n",
			binary, strerror(errno));
		err = -errno;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	printf("tracing SQL queries in %s... Ctrl-C\n", binary);
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
