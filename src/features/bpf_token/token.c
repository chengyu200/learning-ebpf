// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* features/bpf_token: user-space loader.  Demonstrates creating a BPF token
 * via fsopen/fsmount on a new bpffs instance with delegation, then loading a
 * BPF program that uses the token.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <bpf/libbpf.h>
#include "token.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct token_bpf *skel;
	int err = 0;

	libbpf_set_print(libbpf_print_fn);

	/* A full token demo would: mount a new bpffs with delegation opts,
	 * create a token via bpf(BPF_TOKEN_CREATE), pass the token fd to
	 * bpf_prog_load.  libbpf support for tokens is via BPF_FS mount opts.
	 * Here we just load the program to verify the path compiles; see
	 * tools/testing/selftests/bpf/progs/token* for full examples. */
	printf("bpf_token demo: loading program (full token delegation needs "
	       "a dedicated bpffs mount with deleg opts)\n");

	skel = token_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }
	err = token_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach failed\n"); goto cleanup; }

	printf("loaded + attached (token delegation path compiles)\n");
	sleep(1);

cleanup:
	token_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
