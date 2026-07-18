// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 27-replace: user-space loader.
 * Usage: ./replace <from> <to>   (must be same length)
 * e.g. ./replace world eBPF   — replaces "world" with "eBPF" in all reads
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "replace.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct replace_bpf *skel;
	int err = 0;

	if (argc < 3 || strlen(argv[1]) != strlen(argv[2])) {
		fprintf(stderr, "usage: %s <from> <to>  (same length)\n", argv[0]);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = replace_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
	strncpy((char *)skel->rodata->from_str, argv[1], 15);
	strncpy((char *)skel->rodata->to_str, argv[2], 15);
	skel->rodata->from_len = strlen(argv[1]);
	skel->rodata->to_len = strlen(argv[2]);

	printf("replacing '%s' -> '%s' in all reads... Ctrl-C\n", argv[1], argv[2]);

	err = replace_bpf__load(skel);
	if (err) { fprintf(stderr, "load failed\n"); goto cleanup; }
	err = replace_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach failed\n"); goto cleanup; }

	while (!exiting) sleep(1);

cleanup:
	replace_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
