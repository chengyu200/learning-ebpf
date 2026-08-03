// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 59b-iter-tcp: 用户态 — 遍历 TCP 连接，解析二进制输出。
 *
 * 类似 ss -t，输出所有 TCP 连接的四元组 + 状态。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iter-tcp.h"
#include "iter-tcp.skel.h"

static const char *tcp_states[] = {
	[1]  = "ESTABLISHED",
	[2]  = "SYN_SENT",
	[3]  = "SYN_RECV",
	[4]  = "FIN_WAIT1",
	[5]  = "FIN_WAIT2",
	[6]  = "TIME_WAIT",
	[7]  = "CLOSE",
	[8]  = "CLOSE_WAIT",
	[9]  = "LAST_ACK",
	[10] = "LISTEN",
	[11] = "CLOSING",
};

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct iter_tcp_bpf *skel;
	struct bpf_link *link = NULL;
	int err = 0, iter_fd;
	char buf[4096];
	ssize_t n;
	size_t offset = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	skel = iter_tcp_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	link = bpf_program__attach_iter(skel->progs.dump_tcp, NULL);
	if (!link) {
		fprintf(stderr, "attach_iter failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		fprintf(stderr, "bpf_iter_create failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	printf("%-20s %-8s %-20s %-8s %s\n",
	       "Local Address", "Port", "Peer Address", "Port", "State");
	printf("%-20s %-8s %-20s %-8s %s\n",
	       "--------------------", "--------", "--------------------", "--------", "----------");

	while (!exiting && (n = read(iter_fd, buf + offset, sizeof(buf) - offset)) > 0) {
		size_t total = offset + n;
		size_t i = 0;

		while (i + sizeof(struct tcp_event) <= total) {
			struct tcp_event *e = (struct tcp_event *)(buf + i);
			struct in_addr s = { .s_addr = e->saddr };
			struct in_addr d = { .s_addr = e->daddr };
			const char *state = (e->state < 12 && tcp_states[e->state])
				? tcp_states[e->state] : "UNKNOWN";

			printf("%-20s %-8d %-20s %-8d %s\n",
			       inet_ntoa(s), e->sport,
			       inet_ntoa(d), e->dport, state);
			i += sizeof(struct tcp_event);
		}

		if (i < total) {
			memmove(buf, buf + i, total - i);
			offset = total - i;
		} else {
			offset = 0;
		}
	}

	close(iter_fd);

cleanup:
	if (link)
		bpf_link__destroy(link);
	iter_tcp_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
