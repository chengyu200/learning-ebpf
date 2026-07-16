// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 16-memleak (simplified): user-space loader. */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include "memleak.h"
#include "memleak.skel.h"

static struct env {
	pid_t pid;
	char command[128];
	char object[128];
	int interval;
	int top;
	bool verbose;
} env = {
	.pid = -1, .command = {0}, .object = {0},
	.interval = 5, .top = 10,
};

const char *argp_program_version = "memleak 0.1";
const char argp_program_doc[] =
"Trace outstanding memory allocations.\n"
"\n"
"USAGE: ./memleak [--pid PID | --command CMD] [--obj PATH] [-i SEC] [-T N]\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process to trace" },
	{ "command", 'c', "CMD", 0, "Run and trace this command" },
	{ "obj", 'O', "PATH", 0, "Allocator object (default: auto-detect libc)" },
	{ "interval", 'i', "SEC", 0, "Print interval (default 5)" },
	{ "top", 'T', "N", 0, "Show top N stacks (default 10)" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p': env.pid = atoi(arg); break;
	case 'c': strncpy(env.command, arg, sizeof(env.command) - 1); break;
	case 'O': strncpy(env.object, arg, sizeof(env.object) - 1); break;
	case 'i': env.interval = atoi(arg); break;
	case 'T': env.top = atoi(arg); break;
	case 'v': env.verbose = true; break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = argp_program_doc };

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

/* Find the path of the loaded libc by scanning /proc/self/maps. */
static void detect_libc(char *out, size_t out_sz)
{
	FILE *f = fopen("/proc/self/maps", "r");
	char line[512], *p;

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if ((p = strstr(line, "libc.so")) || (p = strstr(line, "libc-"))) {
			char *path = strchr(line, '/');
			if (path) {
				path[strlen(path) - 1] = 0; /* trim newline */
				strncpy(out, path, out_sz - 1);
			}
			break;
		}
	}
	fclose(f);
}

#define ATTACH_UPROBE(prog, sym, is_ret) \
	do { \
		LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = sym, .retprobe = is_ret); \
		struct bpf_link *l = bpf_program__attach_uprobe_opts( \
			skel->progs.prog, env.pid, env.object, 0, &uo); \
		if (!l) { \
			fprintf(stderr, "attach " sym " failed: %s\n", strerror(errno)); \
			err = -errno; \
			goto cleanup; \
		} \
		links[nlinks++] = l; \
	} while (0)

struct agg { __u32 stack_id; __u64 total; __u64 count; };

static int agg_cmp(const void *a, const void *b)
{
	__u64 x = ((const struct agg *)a)->total, y = ((const struct agg *)b)->total;
	return (x < y) - (x > y);
}

static void print_outstanding(struct memleak_bpf *skel)
{
//	int allocs_fd = bpf_map__fd(skel->maps.allocs);
//	int stack_fd = bpf_map__fd(skel->maps.stack_traces);
	__u64 prev = 0, curr = 0;
	struct agg *aggs = NULL;
	int n = 0, cap = 256, i, j;
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char ts[32];

	aggs = calloc(cap, sizeof(*aggs));
	if (!aggs)
		return;

	while (bpf_map__get_next_key(skel->maps.allocs, &prev, &curr, sizeof(curr)) == 0) {
		struct alloc_info info = {};

		if (bpf_map__lookup_elem(skel->maps.allocs, &curr, sizeof(curr),
					 &info, sizeof(info), 0) == 0) {
			for (i = 0; i < n; i++)
				if (aggs[i].stack_id == info.stack_id)
					break;
			if (i == n) {
				if (n >= cap) { cap *= 2; aggs = realloc(aggs, cap * sizeof(*aggs)); }
				aggs[n].stack_id = info.stack_id;
				aggs[n].total = info.size;
				aggs[n].count = 1;
				n++;
			} else {
				aggs[i].total += info.size;
				aggs[i].count++;
			}
		}
		prev = curr;
	}

	qsort(aggs, n, sizeof(*aggs), agg_cmp);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("\n[%s] Top %d outstanding allocation stacks:\n", ts, n < env.top ? n : env.top);

	for (i = 0; i < n && i < env.top; i++) {
		unsigned long long frames[127];
		int ksz = sizeof(frames), got;

		printf("\n%llu bytes in %llu allocs  (stack_id=%d)\n",
		       aggs[i].total, aggs[i].count, aggs[i].stack_id);
		memset(frames, 0, ksz);
		got = bpf_map__lookup_elem(skel->maps.stack_traces,
					   &aggs[i].stack_id, sizeof(aggs[i].stack_id),
					   frames, ksz, 0);
		if (got != 0)
			continue;
		for (j = 0; j < 127 && frames[j]; j++)
			printf("    %016llx\n", frames[j]);
	}
	free(aggs);
}

int main(int argc, char **argv)
{
	struct memleak_bpf *skel;
	struct bpf_link *links[8];
	int nlinks = 0, err = 0, i;
	int pfd[2] = { -1, -1 };
	pid_t child = -1;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGCHLD, sig_handler);

	if (!env.object[0])
		detect_libc(env.object, sizeof(env.object));
	if (!env.object[0]) {
		fprintf(stderr, "Could not auto-detect libc; pass --obj PATH\n");
		return 1;
	}
	printf("using object: %s\n", env.object);

	if (env.command[0]) {
		if (env.pid >= 0) {
			fprintf(stderr, "cannot specify both --pid and --command\n");
			return 1;
		}
		if (pipe(pfd) < 0) { perror("pipe"); return 1; }
		child = fork();
		if (child == 0) {
			char go = 0;
			close(pfd[1]);
			if (read(pfd[0], &go, 1) != 1) _exit(127);
			close(pfd[0]);
			execl("/bin/sh", "sh", "-c", env.command, NULL);
			_exit(127);
		}
		close(pfd[0]); /* parent keeps the write end */
		env.pid = child;
	}

	skel = memleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->target_pid = (env.pid >= 0) ? env.pid : 0;
	skel->rodata->sample_rate = 1;

	/* BPF_MAP_TYPE_STACK_TRACE needs an explicit value size
	 * (max_stack_depth * sizeof(u64)). */
	bpf_map__set_value_size(skel->maps.stack_traces, 127 * sizeof(unsigned long long));

	err = memleak_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	ATTACH_UPROBE(malloc_enter, "malloc", false);
	ATTACH_UPROBE(malloc_exit, "malloc", true);
	ATTACH_UPROBE(calloc_enter, "calloc", false);
	ATTACH_UPROBE(calloc_exit, "calloc", true);
	ATTACH_UPROBE(realloc_enter, "realloc", false);
	ATTACH_UPROBE(realloc_exit, "realloc", true);
	ATTACH_UPROBE(free_enter, "free", false);

	if (child > 0) {
		char go = 1;
		if (write(pfd[1], &go, 1) != 1)
			fprintf(stderr, "failed to notify child\n");
		close(pfd[1]);
	}

	printf("Tracing outstanding allocations... Ctrl-C to end\n");
	while (!exiting) {
		sleep(env.interval);
		print_outstanding(skel);
	}

cleanup:
	for (i = 0; i < nlinks; i++)
		bpf_link__destroy(links[i]);
	memleak_bpf__destroy(skel);
	if (child > 0) {
		kill(child, SIGTERM);
		waitpid(child, NULL, 0);
	}
	return err < 0 ? -err : 0;
}
