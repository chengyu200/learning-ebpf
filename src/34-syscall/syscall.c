// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 34-syscall: user-space loader.  Usage: ./syscall [--pid PID] [--override]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <argp.h>
#include <bpf/libbpf.h>
#include "syscall.skel.h"

static struct env { pid_t pid; bool override; } env = { .pid = 0 };
static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Target PID" },
	{ "override", 'o', NULL, 0, "Deny openat via bpf_override" },
	{},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	if (key == 'p') env.pid = atoi(arg);
	else if (key == 'o') env.override = true;
	else return ARGP_ERR_UNKNOWN;
	return 0;
}
static const struct argp argp = { .options = opts, .parser = parse_arg };

int main(int argc, char **argv)
{
	struct syscall_bpf *skel;
	int err = 0;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = syscall_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
	skel->rodata->target_pid = env.pid;
	skel->rodata->do_override = env.override;

	err = syscall_bpf__load(skel);
	if (err) { fprintf(stderr, "load failed\n"); goto cleanup; }

	if (!env.override)
		bpf_program__set_autoload(skel->progs.override_openat, false);

	err = syscall_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach failed\n"); goto cleanup; }

	printf("syscall tracer running (pid=%d override=%d)... Ctrl-C\n", env.pid, env.override);
	printf("(watch /sys/kernel/tracing/trace_pipe)\n");
	while (!exiting) sleep(1);

cleanup:
	syscall_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
