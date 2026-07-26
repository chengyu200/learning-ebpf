// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-transparent-proxy: 纯 HTTP echo 服务器（无 BPF 依赖）。
 *
 * 监听 127.0.0.1:8080，收到请求后返回简单 HTTP 响应。
 * 被透明代理时无需任何修改。
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
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
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

static void handle_client(int fd)
{
	char buf[1024];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
	} else {
		close(fd);
		return;
	}

	/* 解析 HTTP 请求行第一行 */
	char path[256] = "/";
	ssize_t i;
	int sp = 0;
	for (i = 0; i < n && i < (ssize_t)sizeof(buf) - 1; i++) {
		if (buf[i] == ' ') {
			sp++;
			if (sp == 1) {
				/* 下一字符到空格/CR 之间是 path */
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

	char body[512];
	snprintf(body, sizeof(body),
		 "Hello from server!\r\n"
		 "You requested: %s\r\n"
		 "Server is listening on port %d.\r\n",
		 path, SERVER_PORT);

	char response[768];
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
	sa.sa_flags = 0;  /* 不设 SA_RESTART，确保 accept 被中断 */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	srv_fd = create_server_socket();
	if (srv_fd < 0)
		return 1;
	printf("[server] listening on 127.0.0.1:%d\n", SERVER_PORT);

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
