// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-transparent-proxy-v3: 外部服务进程（在 bpfns netns 内运行）。
 *
 * 监听 192.168.99.2:9090，收到连接后返回简单标识字符串。
 * 用于演示 server 的出流量被 connect4 劫持到 sidecar，再由 sidecar 回源到达此处。
 *
 * 启动方式：ip netns exec bpfns ./external-server
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "proxy.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

int main(void)
{
	int srv_fd, opt = 1;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(EXT_SERVER_PORT),
		.sin_addr.s_addr = inet_addr(EXT_SERVER_IP),
	};

	setvbuf(stdout, NULL, _IONBF, 0);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (srv_fd < 0) {
		fprintf(stderr, "[ext] socket: %s\n", strerror(errno));
		return 1;
	}
	setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "[ext] bind %s:%d: %s\n",
			EXT_SERVER_IP, EXT_SERVER_PORT, strerror(errno));
		close(srv_fd);
		return 1;
	}
	if (listen(srv_fd, 128) < 0) {
		fprintf(stderr, "[ext] listen: %s\n", strerror(errno));
		close(srv_fd);
		return 1;
	}
	printf("[ext] listening on %s:%d (in bpfns netns)\n",
	       EXT_SERVER_IP, EXT_SERVER_PORT);

	while (!exiting) {
		struct sockaddr_in cli;
		socklen_t len = sizeof(cli);
		int cli_fd = accept(srv_fd, (struct sockaddr *)&cli, &len);
		if (cli_fd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		printf("[ext] connection from %s:%d\n",
		       inet_ntoa(cli.sin_addr), ntohs(cli.sin_port));

		char body[256];
		snprintf(body, sizeof(body),
			 "Hello from external-server @ %s:%d!\r\n"
			 "You reached the remote service.\r\n",
			 EXT_SERVER_IP, EXT_SERVER_PORT);

		char resp[384];
		snprintf(resp, sizeof(resp),
			 "HTTP/1.0 200 OK\r\n"
			 "Content-Type: text/plain\r\n"
			 "Content-Length: %zu\r\n"
			 "Connection: close\r\n"
			 "\r\n"
			 "%s",
			 strlen(body), body);

		write(cli_fd, resp, strlen(resp));
		close(cli_fd);
	}
	close(srv_fd);
	return 0;
}
