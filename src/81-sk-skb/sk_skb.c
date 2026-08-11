// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 81-sk-skb: SK_SKB stream parser + verdict — userspace loader + test.
 *
 * Flow:
 *   1. Load BPF skeleton
 *   2. Attach stream_parser and stream_verdict to the SOCKMAP
 *   3. Create TCP server on 127.0.0.1:0 (kernel assigns port)
 *   4. fork child; child connects to server and sends 3 length-prefixed messages
 *   5. Parent accepts connection, adds the client socket to SOCKMAP
 *   6. Parent polls ringbuf for BPF events, then recv()s the messages
 *   7. Cleanup: detach, close sockets
 *
 * Message protocol: [4-byte BE length] [payload]
 *   msg 1: "Hello"     (5 bytes)  -> total 9
 *   msg 2: "World!!"   (7 bytes)  -> total 11
 *   msg 3: "foo"       (3 bytes)  -> total 7
 *
 * Usage:
 *   sudo ./sk_skb
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sk_skb.h"
#include "sk_skb.skel.h"

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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	fprintf(stderr, "[PARSED ] msg_size=%-3u payload=%-3u local_port=%-6u remote_port=%-6u %s\n",
		e->msg_size, e->payload_len,
		e->local_port, ntohs(e->remote_port),
		family_str(e->family));
	return 0;
}

/* Build a length-prefixed message: [4-byte BE length] [payload] */
static int build_msg(char *buf, int bufsz, const char *payload)
{
	int len = strlen(payload);
	if (len + 4 > bufsz)
		return -1;
	__u32 be_len = htonl(len);
	memcpy(buf, &be_len, 4);
	memcpy(buf + 4, payload, len);
	return 4 + len;
}

/* Child: connect to server, send 3 length-prefixed messages */
static void run_child(int port)
{
	int fd;
	char buf[256];

	usleep(100000);  /* wait for parent to listen */

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "\t[child] socket: %s\n", strerror(errno));
		_exit(1);
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "\t[child] connect: %s\n", strerror(errno));
		_exit(1);
	}

	fprintf(stderr, "\t[child] connected to 127.0.0.1:%d\n", port);

	const char *msgs[] = { "Hello", "World!!", "foo" };
	for (int i = 0; i < 3; i++) {
		int n = build_msg(buf, sizeof(buf), msgs[i]);
		if (send(fd, buf, n, 0) < 0) {
			fprintf(stderr, "\t[child] send: %s\n", strerror(errno));
			_exit(1);
		}
		fprintf(stderr, "\t[child] sent msg %d: \"%s\" (%d bytes)\n",
			i + 1, msgs[i], n);
		usleep(200000);  /* small delay between messages */
	}

	close(fd);
	fprintf(stderr, "\t[child] done\n");
	_exit(0);
}

int main(int argc, char **argv)
{
	struct sk_skb_bpf *skel;
	struct bpf_link *links[2] = {};
	struct ring_buffer *ringbuf = NULL;
	int err = 0, server_fd = -1, client_fd = -1;
	int sockmap_fd;
	pid_t child;
	struct sockaddr_in server_addr;
	socklen_t addr_len = sizeof(server_addr);

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	/* 1. Load BPF skeleton */
	skel = sk_skb_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	sockmap_fd = bpf_map__fd(skel->maps.sockmap);

	/* 2. Attach stream_parser and stream_verdict to SOCKMAP */
	struct bpf_program *progs[2] = {
		skel->progs.stream_parser,
		skel->progs.stream_verdict,
	};

	for (int i = 0; i < 2; i++) {
		links[i] = bpf_program__attach_sockmap(progs[i], sockmap_fd);
		if (!links[i]) {
			fprintf(stderr, "attach program %d failed: %s\n", i, strerror(errno));
			err = -errno;
			goto cleanup;
		}
	}

	/* 3. Setup ringbuf */
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	/* 4. Create TCP server on 127.0.0.1:0 */
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	int opt = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	server_addr.sin_port = 0;  /* let kernel assign */

	if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		fprintf(stderr, "bind: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (listen(server_fd, 1) < 0) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	getsockname(server_fd, (struct sockaddr *)&server_addr, &addr_len);
	int port = ntohs(server_addr.sin_port);

	fprintf(stderr, "BPF sk_skb programs attached to SOCKMAP.\n");
	fprintf(stderr, "TCP server listening on 127.0.0.1:%d\n\n", port);

	/* 5. fork child to send messages */
	child = fork();
	if (child == 0) {
		run_child(port);
		_exit(0);
	} else if (child < 0) {
		fprintf(stderr, "fork: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 6. Parent: accept connection */
	client_fd = accept(server_fd, NULL, NULL);
	if (client_fd < 0) {
		fprintf(stderr, "accept: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	fprintf(stderr, "\t[parent] accepted connection\n");

	/* Add client socket to SOCKMAP — this enables BPF programs on it.
	 * From now on, incoming data on client_fd triggers stream_parser
	 * then stream_verdict before reaching userspace recv(). */
	__u32 key = 0;
	__u32 val = client_fd;
	if (bpf_map_update_elem(sockmap_fd, &key, &val, BPF_ANY) < 0) {
		fprintf(stderr, "sockmap update: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	fprintf(stderr, "\t[parent] client socket added to SOCKMAP (key=0)\n\n");

	/* 7. Poll ringbuf + recv messages */
	int msg_count = 0;
	char recvbuf[256];

	while (msg_count < 3) {
		ring_buffer__poll(ringbuf, 50);

		/* Non-blocking recv to get the message from userspace side */
		int flags = fcntl(client_fd, F_GETFL, 0);
		fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

		ssize_t n = recv(client_fd, recvbuf, sizeof(recvbuf), 0);
		if (n > 0) {
			msg_count++;
			/* Extract payload length and text */
			if (n >= 4) {
				__u32 payload_len = ntohl(*(__u32 *)recvbuf);
				char payload[64] = {};
				int copy_len = payload_len < (int)sizeof(payload) - 1 ? payload_len : (int)sizeof(payload) - 1;
				if (n >= 4 + copy_len)
					memcpy(payload, recvbuf + 4, copy_len);
				fprintf(stderr, "[RECV   ] msg %d: \"%s\" (%zd bytes total)\n",
					msg_count, payload, n);
			}
		} else if (n == 0) {
			/* connection closed */
			break;
		}

		fcntl(client_fd, F_SETFL, flags);  /* restore blocking */
		usleep(50000);
	}

	/* Drain remaining ringbuf events */
	ring_buffer__poll(ringbuf, 500);

	/* Wait for child */
	int status;
	waitpid(child, &status, 0);

	fprintf(stderr, "\n%d messages parsed by BPF stream_parser.\n", msg_count);

	/* Remove socket from SOCKMAP before closing */
	__u32 del_key = 0;
	bpf_map_delete_elem(sockmap_fd, &del_key);

cleanup:
	ring_buffer__free(ringbuf);
	for (int i = 0; i < 2; i++)
		if (links[i])
			bpf_link__destroy(links[i]);
	if (skel)
		sk_skb_bpf__destroy(skel);
	if (client_fd >= 0)
		close(client_fd);
	if (server_fd >= 0)
		close(server_fd);
	return err < 0 ? -err : 0;
}
