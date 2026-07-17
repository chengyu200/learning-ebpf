// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Based on agentsight/bpf/sslsniff.c — simplified, OpenSSL only.
 *
 * Attaches uprobes to SSL_read/SSL_write/SSL_read_ex/SSL_write_ex in libssl.
 * Prints captured plaintext data to stdout.
 *
 * Usage: ./sslsniff [--pid PID] [--lib PATH]
 */
#include <argp.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "sslsniff.h"
#include "sslsniff.skel.h"

#define INVALID_PID (-1)

static struct env {
	pid_t pid;       /* -1 = all */
	char *libpath;
	bool verbose;
} env = { .pid = INVALID_PID, .libpath = NULL, .verbose = false };

static volatile sig_atomic_t exiting;

static void sig_int(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "lib", 'l', "PATH", 0, "Path to libssl.so (default: auto-detect)" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p': env.pid = atoi(arg); break;
	case 'l': env.libpath = strdup(arg); break;
	case 'v': env.verbose = true; break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts, .parser = parse_arg,
	.doc = "Capture SSL/TLS plaintext via uprobe on OpenSSL (libssl).",
};

/* Find libssl path via ldconfig (same as agentsight). */
static char *find_libssl(void)
{
	static char path[512];
	FILE *fp = popen("ldconfig -p | grep 'libssl.so'", "r");
	if (!fp) return NULL;
	if (fgets(path, sizeof(path) - 1, fp) != NULL) {
		char *start = strrchr(path, '>');
		if (start && *(start + 1) == ' ') {
			memmove(path, start + 2, strlen(start + 2) + 1);
			char *nl = strchr(path, '\n');
			if (nl) *nl = '\0';
			pclose(fp);
			return path;
		}
	}
	pclose(fp);
	return NULL;
}

/* Attach a single uprobe/uretprobe by function name.  pid=-1 means all procs. */
#define ATTACH(skel, prog, sym, is_ret)                                       \
	do {                                                                  \
		LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = sym,            \
			     .retprobe = is_ret);                              \
		struct bpf_link *l = bpf_program__attach_uprobe_opts(         \
			skel->progs.prog, env.pid, libpath, 0, &uo);          \
		if (!l) {                                                    \
			fprintf(stderr, "attach %s (%s) failed: %s\n",       \
				#prog, sym, strerror(errno));                \
			err = -errno;                                        \
			goto cleanup;                                        \
		}                                                            \
		links[nlinks++] = l;                                         \
	} while (0)

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct probe_SSL_data_t *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	const char *rw_str[] = { "READ", "WRITE", "HANDSHAKE" };
	int rw = e->rw >= 0 && e->rw <= 2 ? e->rw : 0;

	printf("%-8s %-7d %-6s len=%-5u ", ts, e->pid, rw_str[rw], e->len);
	if (e->buf_filled && e->buf_size > 0) {
		/* print printable chars; replace non-printable with '.' */
		for (unsigned int i = 0; i < e->buf_size; i++)
			putchar(isprint(e->buf[i]) ? e->buf[i] : '.');
	}
	printf("\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_link *links[16];
	int nlinks = 0, err = 0, i;
	struct ring_buffer *rb = NULL;
	struct sslsniff_bpf *skel;
	const char *libpath;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	libpath = env.libpath ? env.libpath : find_libssl();
	if (!libpath) {
		fprintf(stderr, "Could not find libssl.so (use --lib PATH)\n");
		return 1;
	}
	printf("using libssl: %s\n", libpath);

	skel = sslsniff_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }

	/* pid: -1 means all processes (fixes the PID-0 bug). */
	skel->rodata->targ_pid = (env.pid == INVALID_PID) ? 0 : env.pid;

	err = sslsniff_bpf__load(skel);
	if (err) { fprintf(stderr, "load failed: %d\n", err); goto cleanup; }

	/* Attach all 8 probes.  env.pid is -1 for "all processes". */
	ATTACH(skel, probe_SSL_rw_enter,      "SSL_write",     false);
	ATTACH(skel, probe_SSL_write_exit,    "SSL_write",     true);
	ATTACH(skel, probe_SSL_rw_enter,      "SSL_read",      false);
	ATTACH(skel, probe_SSL_read_exit,     "SSL_read",      true);
	ATTACH(skel, probe_SSL_rw_ex_enter,   "SSL_write_ex",  false);
	ATTACH(skel, probe_SSL_write_ex_exit, "SSL_write_ex",  true);
	ATTACH(skel, probe_SSL_rw_ex_enter,   "SSL_read_ex",   false);
	ATTACH(skel, probe_SSL_read_ex_exit,  "SSL_read_ex",   true);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; fprintf(stderr, "ringbuf failed\n"); goto cleanup; }

	printf("sslsniff on %s (pid=%d)... Ctrl-C\n", libpath, env.pid);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) { fprintf(stderr, "poll error: %d\n", err); break; }
	}

cleanup:
	ring_buffer__free(rb);
	for (i = 0; i < nlinks; i++) bpf_link__destroy(links[i]);
	sslsniff_bpf__destroy(skel);
	if (env.libpath) free(env.libpath);
	return err < 0 ? -err : 0;
}
