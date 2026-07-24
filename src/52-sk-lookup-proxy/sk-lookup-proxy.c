// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 52-sk-lookup-proxy: 用户态加载器 + 后端 HTTP 服务器。
 *
 * 功能：
 *   1. 创建 TCP listening socket（127.0.0.1:9000）
 *   2. 加载 BPF 程序，将 listening socket fd 写入 SOCKMAP
 *   3. 用 bpf_link_create 挂载到当前网络命名空间
 *   4. accept() 循环：收到连接后返回 HTTP 响应
 *
 * 用法：
 *   sudo ./sk-lookup-proxy
 *   # 另开终端：
 *   curl http://127.0.0.1:8000
 *   curl http://127.0.0.1:8050
 *   curl http://127.0.0.1:8099
 *   curl http://127.0.0.1:7000   # → Connection refused（不在范围）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sk-lookup-proxy.h"
#include "sk-lookup-proxy.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/*
 * 创建后端 HTTP 服务器 listening socket。
 * 绑定 127.0.0.1:9000，设置 SO_REUSEADDR。
 */
static int create_backend_socket(void)
{
	int sock, opt = 1;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(BACKEND_PORT),
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
	};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return -1;
	}

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "bind :%d: %s\n", BACKEND_PORT, strerror(errno));
		close(sock);
		return -1;
	}

	if (listen(sock, 128) < 0) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

/*
 * 处理一个 HTTP 连接：读取请求，返回简单响应。
 */
static void handle_client(int client_fd)
{
	char buf[1024];
	ssize_t n;

	/* 读取 HTTP 请求（不解析，直接读） */
	n = read(client_fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
	}

	/* 构造 HTTP 响应 */
	char body[256];
	snprintf(body, sizeof(body),
		 "Hello from sk_lookup proxy!\r\n"
		 "Backend is listening on port %d.\r\n"
		 "You connected to a port in range %d-%d.\r\n",
		 BACKEND_PORT, PROXY_PORT_START, PROXY_PORT_END);

	char response[512];
	snprintf(response, sizeof(response),
		 "HTTP/1.0 200 OK\r\n"
		 "Content-Type: text/plain\r\n"
		 "Content-Length: %zu\r\n"
		 "\r\n"
		 "%s",
		 strlen(body), body);

	write(client_fd, response, strlen(response));
	close(client_fd);
}

int main(int argc, char **argv)
{
	struct sk_lookup_proxy_bpf *skel;
	int backend_fd = -1, netns_fd = -1, link_fd = -1;
	int err = 0, map_fd, key = 0;
	__u64 sock_val;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	/* ── 第 1 步：创建后端 HTTP 服务器 ── */
	backend_fd = create_backend_socket();
	if (backend_fd < 0) {
		err = 1;
		goto cleanup;
	}
	printf("Backend HTTP server listening on 127.0.0.1:%d\n", BACKEND_PORT);

	/* ── 第 2 步：加载 BPF 骨架 ── */
	skel = sk_lookup_proxy_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* ── 第 3 步：将后端 socket fd 写入 SOCKMAP ──
	 * SOCKMAP 的 value 是 __u64（socket fd 转为 u64） */
	map_fd = bpf_map__fd(skel->maps.backend_socks);
	sock_val = (__u64)backend_fd;
	err = bpf_map_update_elem(map_fd, &key, &sock_val, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to update SOCKMAP: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}
	printf("Backend socket fd=%d written to SOCKMAP\n", backend_fd);

	/* ── 第 4 步：挂载 BPF 程序到当前网络命名空间 ──
	 * sk_lookup 程序挂载到 netns，不是 cgroup 或网卡。
	 * libbpf 1.7 没有封装 attach 函数，需要直接调用 bpf_link_create。 */
	netns_fd = open("/proc/self/ns/net", O_RDONLY);
	if (netns_fd < 0) {
		fprintf(stderr, "Failed to open netns: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	int prog_fd = bpf_program__fd(skel->progs.l7_proxy);
	link_fd = bpf_link_create(prog_fd, netns_fd, BPF_SK_LOOKUP, NULL);
	if (link_fd < 0) {
		fprintf(stderr, "bpf_link_create(BPF_SK_LOOKUP) failed: %s\n",
			strerror(errno));
		err = -errno;
		goto cleanup;
	}

	printf("BPF sk_lookup program attached to netns\n");
	printf("Proxying ports %d-%d → backend :%d\n",
	       PROXY_PORT_START, PROXY_PORT_END, BACKEND_PORT);
	printf("Test: curl http://127.0.0.1:8000  (or any port %d-%d)\n",
	       PROXY_PORT_START, PROXY_PORT_END);
	printf("Ctrl-C to stop\n\n");

	/* ── 第 5 步：accept() 循环 ── */
	while (!exiting) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);
		int client_fd;

		client_fd = accept(backend_fd, (struct sockaddr *)&client_addr, &addr_len);
		if (client_fd < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "accept: %s\n", strerror(errno));
			break;
		}

		printf("[%d] connection from %s:%d\n",
		       client_fd,
		       inet_ntoa(client_addr.sin_addr),
		       ntohs(client_addr.sin_port));

		handle_client(client_fd);
	}

	err = 0;

cleanup:
	if (link_fd >= 0)
		close(link_fd);
	if (netns_fd >= 0)
		close(netns_fd);
	if (backend_fd >= 0)
		close(backend_fd);
	if (skel)
		sk_lookup_proxy_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
