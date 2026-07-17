// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 29-sockops: user-space loader.
 *
 * Loads the two BPF objects (contrack sockops + redirect sk_msg), attaches the
 * sockops program globally, and attaches the sk_msg program to the SOCKHASH
 * map.  Then reads trace_pipe for the connection-tracking debug output.
 */
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "bpf_contrack.skel.h"
#include "bpf_redirect.skel.h"

/* sock_key is re-declared here for the user-space side; the BPF side gets it
 * from bpf_sockmap.h (which pulls in vmlinux.h, incompatible with libbpf.h). */
struct sock_key {
	__u32 sip;
	__u32 dip;
	__u32 sport;
	__u32 dport;
	__u32 family;
};

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void read_trace_pipe(void)
{
	char buf[4096];
	int fd;
	ssize_t n;

	fd = open("/sys/kernel/tracing/trace_pipe", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return;
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);
	close(fd);
}

int main(int argc, char **argv)
{
	struct bpf_contrack_bpf *ct_skel = NULL;
	struct bpf_redirect_bpf *rd_skel = NULL;
	struct bpf_link *sk_msg_link = NULL;
	struct bpf_link *redir_link = NULL;
	int cgroup_fd, err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* sockops program: load + attach to the root cgroup. */
	ct_skel = bpf_contrack_bpf__open_and_load();
	if (!ct_skel) {
		fprintf(stderr, "Failed to open/load contrack skeleton\n");
		return 1;
	}

	cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
	if (cgroup_fd < 0) {
		fprintf(stderr, "Failed to open /sys/fs/cgroup: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	sk_msg_link = bpf_program__attach_cgroup(ct_skel->progs.bpf_sockops_handler, cgroup_fd);
	if (!sk_msg_link) {
		fprintf(stderr, "sockops attach failed: %s\n", strerror(errno));
		err = -errno;
		close(cgroup_fd);
		goto cleanup;
	}
	close(cgroup_fd);

	/* sk_msg program: load, then attach to the shared SOCKHASH map. */
	rd_skel = bpf_redirect_bpf__open_and_load();
	if (!rd_skel) {
		fprintf(stderr, "Failed to open/load redirect skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* Reuse the contrack map in the redirect skeleton so both programs share
	 * the same SOCKHASH instance. */
	err = bpf_map__reuse_fd(rd_skel->maps.sock_ops_map,
				bpf_map__fd(ct_skel->maps.sock_ops_map));
	if (err) {
		fprintf(stderr, "map reuse failed: %s\n", strerror(-err));
		goto cleanup;
	}

	redir_link = bpf_program__attach_sockmap(rd_skel->progs.bpf_redir,
					 bpf_map__fd(rd_skel->maps.sock_ops_map));
	if (!redir_link) {
		err = -errno;
		fprintf(stderr, "sk_msg attach failed: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("sockops + sk_msg attached. Generate local traffic, e.g.:\n");
	printf("  curl -s http://127.0.0.1/\n");
	printf("(trace output follows; Ctrl-C to stop)\n");

	while (!exiting) {
		read_trace_pipe();
		sleep(1);
	}
	err = 0;

cleanup:
	if (redir_link) bpf_link__destroy(redir_link);
	if (sk_msg_link) bpf_link__destroy(sk_msg_link);
	if (rd_skel) bpf_redirect_bpf__destroy(rd_skel);
	if (ct_skel) bpf_contrack_bpf__destroy(ct_skel);
	return err < 0 ? -err : 0;
}
