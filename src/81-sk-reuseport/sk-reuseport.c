// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 81-sk-reuseport: 用户态加载器 + 测试。
 *
 * 流程：
 *   阶段 1：SEC("sk_reuseport") — 仅选择
 *     1. 创建 3 个 TCP listener（SO_REUSEPORT 绑定同一端口）
 *     2. attach select_prog（setsockopt SO_ATTACH_REUSEPORT_EBPF）
 *     3. fork 子进程连接 6 次
 *     4. 父进程 accept 并记录哪个 listener 收到连接
 *     5. 打印 BPF select 事件
 *
 *   阶段 2：SEC("sk_reuseport/migrate") — 选择 + 迁移
 *     6. 替换为 migrate_prog
 *     7. 关闭 listener[2]
 *     8. fork 子进程再连接 3 次
 *     9. 展示剩余 listener 继续工作
 *    10. 打印 BPF migrate 事件
 *
 * 用法：sudo ./sk-reuseport
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sk-reuseport.h"
#include "sk-reuseport.skel.h"

#ifndef SO_ATTACH_REUSEPORT_EBPF
#define SO_ATTACH_REUSEPORT_EBPF 52
#endif

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *op_str(__u8 op)
{
	switch (op) {
	case OP_SELECT:  return "SELECT ";
	case OP_MIGRATE: return "MIGRATE";
	default:         return "UNKNOWN";
	}
}

/* ringbuf 回调 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	printf("  [BPF] %-7s socket[%d]  hash=%u  proto=%d  pid=%u\n",
	       op_str(e->op), e->selected, e->hash, e->ip_protocol, e->pid);
	return 0;
}

/* 创建 NUM_SOCKETS 个 TCP listener，全部绑定同一端口 */
static int create_listeners(int *socks, int *port_out)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};

	for (int i = 0; i < NUM_SOCKETS; i++) {
		socks[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (socks[i] < 0) {
			fprintf(stderr, "\tsocket[%d]: %s\n", i, strerror(errno));
			return -1;
		}

		int opt = 1;
		if (setsockopt(socks[i], SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
			fprintf(stderr, "\tSO_REUSEPORT[%d]: %s\n", i, strerror(errno));
			return -1;
		}

		if (bind(socks[i], (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			fprintf(stderr, "\tbind[%d]: %s\n", i, strerror(errno));
			return -1;
		}

		if (listen(socks[i], 128) < 0) {
			fprintf(stderr, "\tlisten[%d]: %s\n", i, strerror(errno));
			return -1;
		}

		/* 第一个 socket bind 后获取端口，后续 socket 绑定同一端口 */
		if (i == 0) {
			socklen_t alen = sizeof(addr);
			getsockname(socks[i], (struct sockaddr *)&addr, &alen);
			*port_out = ntohs(addr.sin_port);
		}
	}
	return 0;
}

/* attach BPF 程序到 reuseport 组（只需 attach 到一个 socket，对整个组生效） */
static int attach_prog(int sock_fd, int prog_fd)
{
	return setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
			  &prog_fd, sizeof(prog_fd));
}

/* 子进程：连接到 port 多少次 */
static void child_connect(int port, int count)
{
	for (int i = 0; i < count; i++) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			_exit(1);

		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = htons(port),
		};

		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			fprintf(stderr, "\t  [child] connect %d: %s\n", i, strerror(errno));
			close(fd);
			continue;
		}
		/* 保持连接 2 秒，确保父进程 accept 能看到 */
		usleep(2000000);
		close(fd);
	}
	_exit(0);
}

/* 在所有 listener 上 accept，直到子进程退出。
 * 使用非阻塞 accept 轮询。 */
static void accept_loop(int *socks, int num, pid_t child, int *counts)
{
	/* 设置所有 listener 为非阻塞 */
	for (int i = 0; i < num; i++) {
		if (socks[i] < 0)
			continue;
		int flags = fcntl(socks[i], F_GETFL, 0);
		fcntl(socks[i], F_SETFL, flags | O_NONBLOCK);
	}

	int status;
	while (1) {
		/* 检查子进程是否退出 */
		pid_t ret = waitpid(child, &status, WNOHANG);
		bool child_done = (ret != 0);

		/* 轮询所有 listener */
		for (int i = 0; i < num; i++) {
			if (socks[i] < 0)
				continue;

			while (1) {
				int client = accept(socks[i], NULL, NULL);
				if (client < 0)
					break;
				counts[i]++;
				close(client);
			}
		}

		if (child_done)
			break;

		usleep(10000);  /* 10ms 轮询间隔 */
	}

	/* 子进程退出后，再 drain 一次剩余连接 */
	usleep(200000);
	for (int i = 0; i < num; i++) {
		if (socks[i] < 0)
			continue;
		while (1) {
			int client = accept(socks[i], NULL, NULL);
			if (client < 0)
				break;
			counts[i]++;
			close(client);
		}
	}

	/* 恢复阻塞模式 */
	for (int i = 0; i < num; i++) {
		if (socks[i] < 0)
			continue;
		int flags = fcntl(socks[i], F_GETFL, 0);
		fcntl(socks[i], F_SETFL, flags & ~O_NONBLOCK);
	}
}

int main(int argc, char **argv)
{
	struct sk_reuseport_bpf *skel;
	struct ring_buffer *ringbuf = NULL;
	int socks[NUM_SOCKETS] = { -1 };
	int port = 0;
	int err = 0;
	pid_t child;
	int status;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	libbpf_set_print(libbpf_print_fn);

	/* 1. 加载 BPF skeleton */
	skel = sk_reuseport_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	/* 设置 ringbuf */
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	/* 2. 创建 listeners */
	if (create_listeners(socks, &port) < 0) {
		err = 1;
		goto cleanup;
	}

	printf("Created %d TCP listeners with SO_REUSEPORT on port %d\n\n", NUM_SOCKETS, port);

	/* 3. 填充 REUSEPORT_SOCKARRAY map（key=index → value=socket fd） */
	int reuseport_fd = bpf_map__fd(skel->maps.reuseport_array);
	for (int i = 0; i < NUM_SOCKETS; i++) {
		__u32 key = i;
		__u32 val = socks[i];
		if (bpf_map_update_elem(reuseport_fd, &key, &val, BPF_NOEXIST) < 0)
			fprintf(stderr, "Warning: reuseport_array[%d] update: %s\n", i, strerror(errno));
	}

	/* ════════ 阶段 1：sk_reuseport（仅选择）════════ */

	printf("══ Phase 1: SEC(\"sk_reuseport\") — select only ══\n\n");

	int select_fd = bpf_program__fd(skel->progs.select_prog);
	/* attach 到所有 socket（虽然只需一个，但确保覆盖） */
	for (int i = 0; i < NUM_SOCKETS; i++) {
		if (attach_prog(socks[i], select_fd) < 0) {
			fprintf(stderr, "attach select_prog to socks[%d]: %s\n", i, strerror(errno));
			err = 1;
			goto cleanup;
		}
	}
	printf("Attached select_prog to reuseport group\n");

	/* fork 子进程连接 6 次 */
	printf("Making 6 connections...\n\n");
	child = fork();
	if (child == 0) {
		usleep(300000);  /* 等父进程进入 accept_loop */
		child_connect(port, 6);
		_exit(0);
	}

	/* 父进程 accept（轮询直到子进程退出） */
	int counts[NUM_SOCKETS] = { 0 };
	accept_loop(socks, NUM_SOCKETS, child, counts);

	for (int i = 0; i < NUM_SOCKETS; i++)
		printf("  listener[%d] accepted %d connections\n", i, counts[i]);

	/* 消费 ringbuf 事件 */
	printf("\nBPF events:\n");
	while (ring_buffer__poll(ringbuf, 200) > 0)
		;

	/* ════════ 阶段 2：sk_reuseport/migrate（选择 + 迁移）════════ */

	printf("\n══ Phase 2: SEC(\"sk_reuseport/migrate\") — select + migrate ══\n\n");

	/* 替换为 migrate_prog（不关闭 listener，仅演示程序替换 + 选择功能） */
	int migrate_fd = bpf_program__fd(skel->progs.migrate_prog);
	for (int i = 0; i < NUM_SOCKETS; i++) {
		if (attach_prog(socks[i], migrate_fd) < 0) {
			fprintf(stderr, "attach migrate_prog to socks[%d]: %s\n", i, strerror(errno));
			err = 1;
			goto cleanup;
		}
	}
	printf("Replaced with migrate_prog (handles select + migrate)\n");

	/* fork 子进程再连接 3 次（3 个 listener 仍在） */
	printf("Making 3 more connections (same 3 listeners)...\n\n");
	child = fork();
	if (child == 0) {
		usleep(300000);
		child_connect(port, 3);
		_exit(0);
	}

	/* 父进程 accept */
	int counts2[NUM_SOCKETS] = { 0 };
	accept_loop(socks, NUM_SOCKETS, child, counts2);

	for (int i = 0; i < NUM_SOCKETS; i++)
		printf("  listener[%d] accepted %d connections\n", i, counts2[i]);

	/* 消费 ringbuf 事件（包含可能的 MIGRATE 事件） */
	printf("\nBPF events:\n");
	while (ring_buffer__poll(ringbuf, 200) > 0)
		;

	waitpid(child, &status, 0);

	printf("\nDone.\n");

cleanup:
	ring_buffer__free(ringbuf);
	for (int i = 0; i < NUM_SOCKETS; i++) {
		if (socks[i] >= 0)
			close(socks[i]);
	}
	if (skel)
		sk_reuseport_bpf__destroy(skel);
	return err;
}
