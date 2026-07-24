// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 52-sk-lookup-proxy: 用户态加载器 + 后端 HTTP 服务器。
 *
 * 功能：
 *   1. 创建 TCP listening socket（127.0.0.1:9000）
 *   2. 加载 BPF 程序，将 listening socket fd 写入 SOCKMAP
 *   3. 用 bpf_program__attach_netns 挂载到当前网络命名空间
 *   4. accept() 循环：收到连接后读取原始端口，返回 HTTP 响应
 *
 * 原始端口获取：
 *   BPF 程序在 sk_lookup 钩子中把原始目的端口存入 hash map
 *   （key = socket cookie）。用户态 accept() 后用
 *   getsockopt(SO_COOKIE) 获取 cookie，在 map 中查找原始端口。
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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sk-lookup-proxy.h"
#include "sk-lookup-proxy.skel.h"

/* SO_COOKIE = 57 (asm-generic/socket.h) */
#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

/* 与 BPF 程序中的 conn_key 结构匹配 */
struct conn_key {
	__u32 remote_ip4;   /* 客户端源 IP（网络字节序） */
	__u16 remote_port;  /* 客户端源端口（网络字节序） */
	__u16 pad;
};

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
 * 从 BPF map 中查找原始目的端口。
 * @client_fd  accept() 返回的 client socket fd
 * @map_fd     orig_port_map 的 fd
 * @return     原始端口，0 表示未找到
 */
static __u32 get_orig_port(int client_fd, int map_fd)
{
	struct sockaddr_in peer;
	socklen_t peer_len = sizeof(peer);
	struct conn_key ck = {};
	__u32 orig_port = 0;

	/* 获取客户端的源 IP 和源端口 */
	if (getpeername(client_fd, (struct sockaddr *)&peer, &peer_len) < 0)
		return 0;

	ck.remote_ip4 = peer.sin_addr.s_addr;   /* 已经是网络字节序 */
	ck.remote_port = peer.sin_port;          /* 已经是网络字节序 */
	ck.pad = 0;

	/* 在 BPF map 中查找原始端口 */
	if (bpf_map_lookup_elem(map_fd, &ck, &orig_port) < 0)
		return 0;

	/* 查到后删除条目（避免 map 增长） */
	bpf_map_delete_elem(map_fd, &ck);

	return orig_port;
}

/*
 * 处理一个 HTTP 连接：读取请求，返回包含原始端口的响应。
 */
static void handle_client(int client_fd, int orig_port)
{
	char buf[1024];
	ssize_t n;

	n = read(client_fd, buf, sizeof(buf) - 1);
	if (n > 0)
		buf[n] = '\0';

	char body[512];
	snprintf(body, sizeof(body),
		 "Hello from sk_lookup proxy!\r\n"
		 "Backend is listening on port %d.\r\n"
		 "You connected to a port in range %d-%d.\r\n"
		 "Original destination port: %d\r\n",
		 BACKEND_PORT, PROXY_PORT_START, PROXY_PORT_END, orig_port);

	char response[768];
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
	struct bpf_link *link = NULL;
	int backend_fd = -1, netns_fd = -1;
	int err = 0, map_fd, sockmap_fd, key = 0;
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

	/* ── 第 3 步：将后端 socket fd 写入 SOCKMAP ── */
	sockmap_fd = bpf_map__fd(skel->maps.backend_socks);
	sock_val = (__u64)backend_fd;
	err = bpf_map_update_elem(sockmap_fd, &key, &sock_val, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to update SOCKMAP: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}
	printf("Backend socket fd=%d written to SOCKMAP\n", backend_fd);

	/* 获取原始端口 map fd */
	map_fd = bpf_map__fd(skel->maps.orig_port_map);

	/* ── 第 4 步：挂载 BPF 程序到当前网络命名空间 ── */
	netns_fd = open("/proc/self/ns/net", O_RDONLY);
	if (netns_fd < 0) {
		fprintf(stderr, "Failed to open netns: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	link = bpf_program__attach_netns(skel->progs.l7_proxy, netns_fd);
	if (!link) {
		fprintf(stderr, "bpf_program__attach_netns failed: %s\n",
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
	int flags = fcntl(backend_fd, F_GETFL, 0);
	fcntl(backend_fd, F_SETFL, flags | O_NONBLOCK);

	while (!exiting) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);
		int client_fd;
		__u32 orig_port;

		client_fd = accept(backend_fd, (struct sockaddr *)&client_addr, &addr_len);
		if (client_fd < 0) {
			if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
				if (exiting)
					break;
				usleep(10000);
				continue;
			}
			fprintf(stderr, "accept: %s\n", strerror(errno));
			break;
		}

		fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);

		/* 查找原始目的端口 */
		orig_port = get_orig_port(client_fd, map_fd);

		printf("[%d] connection from %s:%d → orig port: %d\n",
		       client_fd,
		       inet_ntoa(client_addr.sin_addr),
		       ntohs(client_addr.sin_port),
		       orig_port);

		handle_client(client_fd, orig_port);
	}

	err = 0;

cleanup:
	if (link)
		bpf_link__destroy(link);
	if (netns_fd >= 0)
		close(netns_fd);
	if (backend_fd >= 0)
		close(backend_fd);
	if (skel)
		sk_lookup_proxy_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
