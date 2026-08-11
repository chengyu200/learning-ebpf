// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 82-cgroup-skb: Cgroup dual-direction traffic audit + egress port policy.
 *
 * Flow:
 *   1. Create dedicated child cgroup
 *   2. Load BPF skeleton, set blocked port in config map
 *   3. Attach ingress + egress programs via bpf_program__attach_cgroup
 *   4. fork child; child writes PID to cgroup.procs to join the cgroup
 *   5. Child:
 *      a. Start TCP server on 127.0.0.1:8080
 *      b. Connect to 127.0.0.1:8080 (allowed — not blocked)
 *      c. Try connect to 127.0.0.1:9999 (blocked — SYN dropped, timeout)
 *      d. Send data on allowed connection
 *      e. Close, exit
 *   6. Parent polls ringbuf, prints events
 *   7. Cleanup: detach + destroy + rmdir
 *
 * Usage:
 *   sudo ./cgroup_skb
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup_skb.h"
#include "cgroup_skb.skel.h"

#define BLOCKED_PORT 9999
#define SERVER_PORT  8080

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *dir_str(__u8 dir)
{
	return dir == DIR_INGRESS ? "INGRESS" : "EGRESS";
}

static const char *proto_str(__u32 proto)
{
	switch (proto) {
	case IPPROTO_TCP:  return "TCP";
	case IPPROTO_UDP:  return "UDP";
	case IPPROTO_ICMP: return "ICMP";
	default:           return "?";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	fprintf(stderr, "[%s] proto=%-4s port=%-6u size=%-4u  %s  pid=%u comm=%s\n",
		dir_str(e->direction),
		proto_str(e->protocol),
		e->port, e->pkt_len,
		e->allowed ? "ALLOWED" : "DENIED",
		e->pid, e->comm);
	return 0;
}

/* Child: join cgroup, start TCP server, test connections */
static void run_in_cgroup(void)
{
	char buf[32];
	int fd, server_fd, client_fd;
	struct sockaddr_in addr;

	/* Write PID to cgroup.procs */
	fd = open(DEMO_CGROUP "/cgroup.procs", O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "\t[child] open cgroup.procs: %s\n", strerror(errno));
		_exit(1);
	}
	snprintf(buf, sizeof(buf), "%d", getpid());
	write(fd, buf, strlen(buf));
	close(fd);
	usleep(100000);
	fprintf(stderr, "\t[child] moved into cgroup (pid=%d)\n\n", getpid());

	/* Start TCP server on 127.0.0.1:8080 */
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		fprintf(stderr, "\t[child] server socket: %s\n", strerror(errno));
		_exit(1);
	}
	int opt = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(SERVER_PORT);

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "\t[child] server bind: %s\n", strerror(errno));
		_exit(1);
	}
	if (listen(server_fd, 1) < 0) {
		fprintf(stderr, "\t[child] listen: %s\n", strerror(errno));
		_exit(1);
	}
	fprintf(stderr, "\t[child] TCP server on 127.0.0.1:%d\n", SERVER_PORT);

	/* Test 1: connect to 127.0.0.1:8080 (allowed) */
	fprintf(stderr, "\t[child] connect 127.0.0.1:%d... \n", SERVER_PORT);
	fflush(stderr);
	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(SERVER_PORT);

	if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "\tFAIL: %s\n", strerror(errno));
		_exit(1);
	}
	fprintf(stderr, "\tOK (allowed)\n");

	/* Accept the connection (triggers ingress events) */
	int accepted = accept(server_fd, NULL, NULL);
	if (accepted >= 0) {
		/* Send data (triggers egress events) */
		const char *msg = "hello from cgroup";
		send(client_fd, msg, strlen(msg), 0);
		usleep(100000);
		close(accepted);
	}
	close(client_fd);
	usleep(200000);

	/* Test 2: connect to 127.0.0.1:9999 (blocked — SYN dropped) */
	fprintf(stderr, "\t[child] connect 127.0.0.1:%d (blocked)... \n", BLOCKED_PORT);
	fflush(stderr);
	client_fd = socket(AF_INET, SOCK_STREAM, 0);

	/* Set 1-second connect timeout via SO_SNDTIMEO */
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(BLOCKED_PORT);

	if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "\tBLOCKED (%s)\n\n", strerror(errno));
	} else {
		fprintf(stderr, "\tUNEXPECTED: connected (should be blocked)\n\n");
		close(client_fd);
	}

	close(server_fd);
	fprintf(stderr, "\t[child] done\n");
	_exit(0);
}

int main(int argc, char **argv)
{
	struct cgroup_skb_bpf *skel;
	struct bpf_link *links[2] = {};
	struct ring_buffer *ringbuf = NULL;
	int err = 0, cg_fd = -1;
	pid_t child;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	/* 1. Create dedicated child cgroup */
	if (mkdir(DEMO_CGROUP, 0755) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir %s: %s\n", DEMO_CGROUP, strerror(errno));
		return 1;
	}
	cg_fd = open(DEMO_CGROUP, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "open %s: %s\n", DEMO_CGROUP, strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 2. Load BPF skeleton */
	skel = cgroup_skb_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* Set blocked egress port in config map */
	__u32 key = 0, blocked_port = BLOCKED_PORT;
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.cfg_block_port), &key, &blocked_port, BPF_ANY) < 0) {
		fprintf(stderr, "set blocked port: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 3. Attach ingress + egress programs to cgroup */
	struct bpf_program *progs[2] = {
		skel->progs.count_ingress,
		skel->progs.filter_egress,
	};

	for (int i = 0; i < 2; i++) {
		links[i] = bpf_program__attach_cgroup(progs[i], cg_fd);
		if (!links[i]) {
			fprintf(stderr, "attach program %d failed: %s\n", i, strerror(errno));
			err = -errno;
			goto cleanup;
		}
	}

	/* 4. Setup ringbuf */
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	fprintf(stderr, "BPF cgroup_skb programs attached to %s\n", DEMO_CGROUP);
	fprintf(stderr, "  ingress: count_ingress  (BPF_CGROUP_INET_INGRESS)\n");
	fprintf(stderr, "  egress:  filter_egress   (BPF_CGROUP_INET_EGRESS)\n");
	fprintf(stderr, "  Blocked egress port: %d\n\n", BLOCKED_PORT);
	fprintf(stderr, "Child (in cgroup) testing:\n\n");

	/* 5. fork child into cgroup */
	child = fork();
	if (child == 0) {
		run_in_cgroup();
		_exit(0);
	} else if (child < 0) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 6. Parent: poll ringbuf while child runs */
	int status;
	while (waitpid(child, &status, WNOHANG) == 0)
		ring_buffer__poll(ringbuf, 50);

	/* Drain remaining events */
	ring_buffer__poll(ringbuf, 500);

	fprintf(stderr, "\nDone. Egress to port %d was blocked by BPF.\n", BLOCKED_PORT);

cleanup:
	ring_buffer__free(ringbuf);
	for (int i = 0; i < 2; i++)
		if (links[i])
			bpf_link__destroy(links[i]);
	if (skel)
		cgroup_skb_bpf__destroy(skel);
	if (cg_fd >= 0)
		close(cg_fd);
	rmdir(DEMO_CGROUP);
	return err < 0 ? -err : 0;
}
