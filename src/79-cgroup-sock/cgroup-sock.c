// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 79-cgroup-sock: Socket lifecycle auditor - userspace loader.
 *
 * Flow:
 *   1. Create dedicated child cgroup
 *   2. Load BPF skeleton
 *   3. Attach 4 programs via bpf_program__attach_cgroup (manual, not auto-attach)
 *   4. fork child; child writes PID to cgroup.procs to join the cgroup
 *   5. Child performs socket operations:
 *      - TCP IPv4 socket + bind 127.0.0.1:0 -> CREATE + BIND4 events
 *      - TCP IPv6 socket + bind [::1]:0      -> CREATE + BIND6 events
 *      - UDP IPv4 socket                     -> CREATE event
 *      - raw socket (IPPROTO_RAW)            -> CREATE event (DENIED)
 *      - close all sockets                   -> RELEASE events
 *   6. Parent polls ringbuf, prints events
 *   7. Cleanup: detach + destroy + rmdir
 *
 * Usage:
 *   sudo ./cgroup-sock
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup-sock.h"
#include "cgroup-sock.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *family_str(__u32 family)
{
	switch (family) {
	case AF_INET:  return "AF_INET";
	case AF_INET6: return "AF_INET6";
	default:       return "AF_????";
	}
}

static const char *sock_type_str(__u32 type)
{
	switch (type) {
	case SOCK_STREAM: return "SOCK_STREAM";
	case SOCK_DGRAM:  return "SOCK_DGRAM";
	case SOCK_RAW:    return "SOCK_RAW";
	default:          return "SOCK_????";
	}
}

static const char *proto_str(__u32 proto)
{
	switch (proto) {
	case 0:   return "default";
	case 6:   return "TCP";
	case 17:  return "UDP";
	case 255: return "RAW";
	default:  return "?";
	}
}

static const char *ev_type_str(__u8 type)
{
	switch (type) {
	case EV_SOCK_CREATE:  return "CREATE";
	case EV_SOCK_RELEASE: return "RELEASE";
	case EV_BIND4:        return "BIND4";
	case EV_BIND6:        return "BIND6";
	default:              return "?";
	}
}

static void format_ip4(__u32 ip4, char *buf, size_t sz)
{
	snprintf(buf, sz, "%u.%u.%u.%u",
		ip4 & 0xFF, (ip4 >> 8) & 0xFF,
		(ip4 >> 16) & 0xFF, (ip4 >> 24) & 0xFF);
}

static void format_ip6(const __u32 ip6[4], char *buf, size_t sz)
{
	struct in6_addr addr;
	memcpy(addr.s6_addr32, ip6, 16);
	inet_ntop(AF_INET6, &addr, buf, sz);
}

/* Ringbuf callback — use stderr so output doesn't interleave with child's stderr */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	char ipbuf[64];

	fprintf(stderr, "[%-7s] pid=%-6u comm=%-12s %-9s %-12s proto=%-7s",
		ev_type_str(e->type),
		e->pid, e->comm,
		family_str(e->family),
		sock_type_str(e->sock_type),
		proto_str(e->protocol));

	if (e->type == EV_SOCK_CREATE)
		fprintf(stderr, "  %s", e->allowed ? "ALLOWED" : "DENIED");
	else if (e->type == EV_BIND4) {
		format_ip4(e->src_ip4, ipbuf, sizeof(ipbuf));
		fprintf(stderr, "  %s:%u", ipbuf, e->src_port);
	} else if (e->type == EV_BIND6) {
		format_ip6(e->src_ip6, ipbuf, sizeof(ipbuf));
		fprintf(stderr, "  [%s]:%u", ipbuf, e->src_port);
	}

	fprintf(stderr, "\n");
	return 0;
}

/* Child: join cgroup and perform socket operations */
static void run_in_cgroup(void)
{
	char buf[32];
	int fd;

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

	/* Test 1: TCP IPv4 socket + bind 127.0.0.1:0 */
	fprintf(stderr, "\t[child] test 1: TCP IPv4 socket + bind...\n");
	int tcp4 = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp4 < 0) {
		fprintf(stderr, "\t[child] FAIL: socket(AF_INET, SOCK_STREAM): %s\n", strerror(errno));
		_exit(1);
	}
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,  /* let kernel pick a port */
	};
	if (bind(tcp4, (struct sockaddr *)&addr4, sizeof(addr4)) < 0) {
		fprintf(stderr, "\t[child] FAIL: bind IPv4: %s\n", strerror(errno));
		_exit(1);
	}
	fprintf(stderr, "\t[child] PASS: TCP IPv4 socket + bind\n\n");

	/* Test 2: TCP IPv6 socket + bind [::1]:0 */
	fprintf(stderr, "\t[child] test 2: TCP IPv6 socket + bind...\n");
	int tcp6 = socket(AF_INET6, SOCK_STREAM, 0);
	if (tcp6 < 0) {
		fprintf(stderr, "\t[child] FAIL: socket(AF_INET6, SOCK_STREAM): %s\n", strerror(errno));
		_exit(1);
	}
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = in6addr_loopback,
		.sin6_port = 0,
	};
	if (bind(tcp6, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
		fprintf(stderr, "\t[child] FAIL: bind IPv6: %s\n", strerror(errno));
		_exit(1);
	}
	fprintf(stderr, "\t[child] PASS: TCP IPv6 socket + bind\n\n");

	/* Test 3: UDP IPv4 socket (no bind, just create) */
	fprintf(stderr, "\t[child] test 3: UDP IPv4 socket...\n");
	int udp4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp4 < 0) {
		fprintf(stderr, "\t[child] FAIL: socket(AF_INET, SOCK_DGRAM): %s\n", strerror(errno));
		_exit(1);
	}
	fprintf(stderr, "\t[child] PASS: UDP IPv4 socket\n\n");

	/* Test 4: raw socket (IPPROTO_RAW) — should be DENIED */
	fprintf(stderr, "\t[child] test 4: raw socket (IPPROTO_RAW)...\n");
	int raw = socket(AF_INET, SOCK_RAW, 255);
	if (raw < 0) {
		fprintf(stderr, "\t[child] PASS: raw socket denied (%s)\n\n", strerror(errno));
	} else {
		close(raw);
		fprintf(stderr, "\t[child] UNEXPECTED: raw socket created (should be denied)\n\n");
	}

	/* Close all sockets — triggers RELEASE events */
	fprintf(stderr, "\t[child] closing all sockets...\n");
	close(tcp4);
	close(tcp6);
	close(udp4);

	fprintf(stderr, "\t[child] All tests done.\n");
	_exit(0);
}

int main(int argc, char **argv)
{
	struct cgroup_sock_bpf *skel;
	struct bpf_link *links[4] = {};
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
	skel = cgroup_sock_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* 3. Attach 4 programs to cgroup (manual attach, not auto-attach) */
	struct bpf_program *progs[4] = {
		skel->progs.sock_create,
		skel->progs.post_bind4,
		skel->progs.post_bind6,
		skel->progs.sock_release,
	};

	for (int i = 0; i < 4; i++) {
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

	fprintf(stderr, "BPF cgroup-sock programs attached to %s\n", DEMO_CGROUP);
	fprintf(stderr, "  Programs:\n");
	fprintf(stderr, "    1. cgroup/sock_create  (BPF_CGROUP_INET_SOCK_CREATE)\n");
	fprintf(stderr, "    2. cgroup/post_bind4   (BPF_CGROUP_INET4_POST_BIND)\n");
	fprintf(stderr, "    3. cgroup/post_bind6   (BPF_CGROUP_INET6_POST_BIND)\n");
	fprintf(stderr, "    4. cgroup/sock_release (BPF_CGROUP_INET_SOCK_RELEASE)\n");
	fprintf(stderr, "\nNote: SEC(\"cgroup/sock\") is a legacy alias for cgroup/sock_create.\n");
	fprintf(stderr, "Policy: raw sockets (IPPROTO_RAW) are denied.\n\n");
	fprintf(stderr, "Child (in cgroup) testing socket operations:\n\n");

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
		ring_buffer__poll(ringbuf, 100);

	/* Drain remaining events */
	ring_buffer__poll(ringbuf, 200);

	fprintf(stderr, "\nDone. Events above show the socket lifecycle.\n");

cleanup:
	ring_buffer__free(ringbuf);
	for (int i = 0; i < 4; i++)
		if (links[i])
			bpf_link__destroy(links[i]);
	if (skel)
		cgroup_sock_bpf__destroy(skel);
	if (cg_fd >= 0)
		close(cg_fd);
	rmdir(DEMO_CGROUP);
	return err < 0 ? -err : 0;
}
