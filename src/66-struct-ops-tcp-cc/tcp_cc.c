// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 66-struct-ops-tcp-cc: 用户态 — 注册 BPF CC + 测试 + ringbuf 轮询。
 *
 * 流程：
 *   1. 加载 BPF skeleton（struct_ops 自动注册 CC 到内核）
 *   2. 验证 /proc/sys/net/ipv4/tcp_available_congestion_control 包含 CC_NAME
 *   3. 同进程创建 TCP server + client（避免 fork 的信号问题）
 *   4. client 设置 setsockopt(TCP_CONGESTION) 选择 BPF CC
 *   5. 传输数据，触发 CC 回调
 *   6. ringbuf 轮询，打印 CC 事件
 *   7. Ctrl-C 退出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcp_cc.h"
#include "tcp_cc.skel.h"

#define TEST_PORT    19090
#define TEST_DATA    "Hello from BPF CC test!"
#define TEST_DATA_LEN (sizeof(TEST_DATA) - 1)

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

static const char *state_names[] = {
	[0] = "Open",
	[1] = "Disorder",
	[2] = "CWR",
	[3] = "Recovery",
	[4] = "Loss",
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct cc_event *e = data;
	(void)ctx;

	switch (e->type) {
	case EV_INIT:
		printf("[INIT]    pid=%-6d  CC initialized for connection\n", e->pid);
		break;
	case EV_CWND:
		printf("[CWND]    pid=%-6d  cwnd=%-5u ssthresh=%u\n",
		       e->pid, e->cwnd, e->ssthresh);
		break;
	case EV_STATE:
		printf("[STATE]   pid=%-6d  -> %s\n", e->pid,
		       (e->state < 5 && state_names[e->state]) ?
		       state_names[e->state] : "Unknown");
		break;
	case EV_RELEASE:
		printf("[RELEASE] pid=%-6d  connection released\n", e->pid);
		break;
	default:
		printf("[????]    pid=%-6d  unknown event %d\n", e->pid, e->type);
	}
	return 0;
}

/* 检查 CC 是否已注册到内核 */
static int check_cc_registered(void)
{
	FILE *f;
	char buf[1024];

	f = fopen("/proc/sys/net/ipv4/tcp_available_congestion_control", "r");
	if (!f)
		return -1;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);

	if (strstr(buf, CC_NAME)) {
		printf("CC '%s' registered: %s", CC_NAME, buf);
		return 0;
	}
	fprintf(stderr, "CC '%s' NOT found in: %s", CC_NAME, buf);
	return -1;
}

int main(int argc, char **argv)
{
	struct tcp_cc_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err = 0, srv_fd = -1, cli_fd = -1, conn_fd = -1;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(TEST_PORT),
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
	};

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* 1. 加载 + 注册 struct_ops CC */
	skel = tcp_cc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	err = tcp_cc_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(-err));
		goto cleanup;
	}

	/* 2. 验证 CC 已注册 */
	if (check_cc_registered() < 0) {
		err = 1;
		goto cleanup;
	}

	/* 3. 创建 ringbuf */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		err = 1;
		goto cleanup;
	}

	/* 4. 创建 TCP server socket（同进程，避免 fork 信号问题） */
	srv_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (srv_fd < 0) {
		fprintf(stderr, "server socket: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	int opt = 1;
	setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "bind: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	if (listen(srv_fd, 1) < 0) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 5. 创建 client socket，设置 BPF CC */
	cli_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (cli_fd < 0) {
		fprintf(stderr, "client socket: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (setsockopt(cli_fd, IPPROTO_TCP, TCP_CONGESTION,
		       CC_NAME, strlen(CC_NAME)) < 0) {
		fprintf(stderr, "setsockopt(TCP_CONGESTION): %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	printf("Set TCP_CONGESTION=%s on client socket\n", CC_NAME);

	/* 6. 连接（非阻塞，立即返回 EINPROGRESS） */
	if (connect(cli_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS) {
		fprintf(stderr, "connect: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 7. accept server 端连接 */
	struct sockaddr_in caddr;
	socklen_t clen = sizeof(caddr);
	conn_fd = accept(srv_fd, (struct sockaddr *)&caddr, &clen);
	if (conn_fd < 0) {
		fprintf(stderr, "accept: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Connected! Sending data...\n\n");

	/* 8. 传输数据触发 CC 回调 */
	write(cli_fd, TEST_DATA, TEST_DATA_LEN);
	char rbuf[256];
	read(conn_fd, rbuf, sizeof(rbuf));
	write(conn_fd, rbuf, TEST_DATA_LEN);
	read(cli_fd, rbuf, sizeof(rbuf));
	printf("Echo received: %.*s\n\n", (int)TEST_DATA_LEN, rbuf);

	/* 9. 轮询 ringbuf 获取 CC 事件 */
	printf("--- CC Events ---\n");
	for (int i = 0; i < 100 && !exiting; i++)
		ring_buffer__poll(rb, 100);

	/* 10. 关闭连接（触发 release 回调） */
	close(cli_fd);
	cli_fd = -1;
	close(conn_fd);
	conn_fd = -1;

	/* 接收 release 事件 */
	for (int i = 0; i < 10 && !exiting; i++)
		ring_buffer__poll(rb, 100);

	printf("\n--- Done ---\n");

cleanup:
	if (cli_fd >= 0) close(cli_fd);
	if (conn_fd >= 0) close(conn_fd);
	if (srv_fd >= 0) close(srv_fd);
	if (rb) ring_buffer__free(rb);
	tcp_cc_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
