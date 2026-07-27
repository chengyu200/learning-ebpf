// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-transparent-proxy-v4: 业务服务进程（纯 socket，无 BPF 侵入）。
 *
 * v4 关键变化：server 监听 0.0.0.0:8080（与用户访问端口一致）。
 * 防回环由 sk_lookup PID 排除实现，server 无需感知。
 *
 * 收到 GET /outbound 时主动 connect 192.168.99.2:9090（演示出流量劫持）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "proxy.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int create_server_socket(void)
{
	int sock, opt = 1;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(SERVER_PORT),
		.sin_addr.s_addr = INADDR_ANY,  /* 0.0.0.0，接受所有地址 */
	};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "[server] socket: %s\n", strerror(errno));
		return -1;
	}
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "[server] bind :%d: %s\n", SERVER_PORT, strerror(errno));
		close(sock);
		return -1;
	}
	if (listen(sock, 128) < 0) {
		fprintf(stderr, "[server] listen: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

static int fetch_external(char *buf, size_t bufsz)
{
	int fd, n;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(EXT_SERVER_PORT),
		.sin_addr.s_addr = inet_addr(EXT_SERVER_IP),
	};

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		snprintf(buf, bufsz, "external connect failed: %s", strerror(errno));
		return -1;
	}
	printf("[server] connecting to external %s:%d (should be hijacked to sidecar)\n",
	       EXT_SERVER_IP, EXT_SERVER_PORT);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		snprintf(buf, bufsz, "external connect: %s", strerror(errno));
		close(fd);
		return -1;
	}

	n = read(fd, buf, bufsz - 1);
	if (n < 0) {
		snprintf(buf, bufsz, "external read: %s", strerror(errno));
		close(fd);
		return -1;
	}
	buf[n] = '\0';
	close(fd);
	return 0;
}

static void handle_client(int fd)
{
	char buf[2048], path[256] = "/";
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	if (n <= 0) {
		close(fd);
		return;
	}
	buf[n] = '\0';

	ssize_t i;
	int sp = 0;
	for (i = 0; i < n; i++) {
		if (buf[i] == ' ') {
			sp++;
			if (sp == 1) {
				size_t j = i + 1, k = 0;
				while (j < (size_t)n && buf[j] != ' ' &&
				       buf[j] != '\r' && buf[j] != '\n' &&
				       k < sizeof(path) - 1)
					path[k++] = buf[j++];
				path[k] = '\0';
				break;
			}
		}
	}

	char body[1024];

	if (strcmp(path, "/outbound") == 0) {
		char ext_data[512];
		fetch_external(ext_data, sizeof(ext_data));
		snprintf(body, sizeof(body),
			 "Hello from server!\r\n"
			 "You requested: %s\r\n"
			 "External service response: %s\r\n"
			 "Server is listening on port %d.\r\n",
			 path, ext_data, SERVER_PORT);
	} else {
		snprintf(body, sizeof(body),
			 "Hello from server!\r\n"
			 "You requested: %s\r\n"
			 "Server is listening on port %d.\r\n",
			 path, SERVER_PORT);
	}

	char response[1536];
	snprintf(response, sizeof(response),
		 "HTTP/1.0 200 OK\r\n"
		 "Content-Type: text/plain\r\n"
		 "Content-Length: %zu\r\n"
		 "Connection: close\r\n"
		 "\r\n"
		 "%s",
		 strlen(body), body);

	write(fd, response, strlen(response));
	close(fd);
}

int main(void)
{
	int srv_fd;

	setvbuf(stdout, NULL, _IONBF, 0);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	srv_fd = create_server_socket();
	if (srv_fd < 0)
		return 1;
	printf("[server] listening on 0.0.0.0:%d (inbound :%d hijacked by sk_lookup)\n",
	       SERVER_PORT, VIRTUAL_PORT);

	while (!exiting) {
		struct sockaddr_in cli;
		socklen_t len = sizeof(cli);
		int cli_fd = accept(srv_fd, (struct sockaddr *)&cli, &len);
		if (cli_fd < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "[server] accept: %s\n", strerror(errno));
			break;
		}
		printf("[server] connection from %s:%d\n",
		       inet_ntoa(cli.sin_addr), ntohs(cli.sin_port));
		handle_client(cli_fd);
	}
	close(srv_fd);
	return 0;
}
