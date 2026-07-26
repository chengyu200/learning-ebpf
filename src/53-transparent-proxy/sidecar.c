// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-transparent-proxy: 用户态 sidecar（BPF loader + TCP 代理 + cgroup 管理）。
 *
 * 职责：
 *   1. 创建专用子 cgroup 并移入自身（避免影响宿主其他进程）
 *   2. 加载 BPF 骨架，写自身 PID 到 sidecar_pid_map 防递归
 *   3. attach cgroup/connect4 + sockops 到该 cgroup
 *   4. listen 127.0.0.1:15006 接收被劫持的连接
 *   5. accept() 后用 getpeername 取客户端源 {ip,port}，查 conn_map 得原始目的，
 *      再 connect() 到原始目的（sidecar PID 被 BPF 跳过），双向 pipe 转发
 *   6. SIGINT 优雅退出，销毁 link/skeleton + rmdir cgroup
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "proxy.h"
#include "sidecar.skel.h"

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

static int create_listening_socket(void)
{
	int sock, opt = 1;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(SIDECAR_PORT),
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
	};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "[sidecar] socket: %s\n", strerror(errno));
		return -1;
	}
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "[sidecar] bind :%d: %s\n", SIDECAR_PORT, strerror(errno));
		close(sock);
		return -1;
	}
	if (listen(sock, 128) < 0) {
		fprintf(stderr, "[sidecar] listen: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

/* 把进程自身移入子 cgroup，返回 cgroup fd（用于 attach）；失败返回 -1 */
static int setup_cgroup(void)
{
	int cg_fd;

	if (mkdir(DEMO_CGROUP, 0755) < 0 && errno != EEXIST) {
		fprintf(stderr, "[sidecar] mkdir %s: %s\n", DEMO_CGROUP, strerror(errno));
		return -1;
	}

	/* 写自身 PID 到 cgroup.procs */
	cg_fd = open(DEMO_CGROUP "/cgroup.procs", O_WRONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "[sidecar] open cgroup.procs: %s\n", strerror(errno));
		rmdir(DEMO_CGROUP);
		return -1;
	}
	char pidbuf[32];
	int len = snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
	if (write(cg_fd, pidbuf, len) != len) {
		fprintf(stderr, "[sidecar] write cgroup.procs: %s\n", strerror(errno));
		close(cg_fd);
		rmdir(DEMO_CGROUP);
		return -1;
	}
	close(cg_fd);

	/* 打开 cgroup 目录作为 fd 给 bpf_program__attach_cgroup */
	cg_fd = open(DEMO_CGROUP, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "[sidecar] open %s: %s\n", DEMO_CGROUP, strerror(errno));
		rmdir(DEMO_CGROUP);
		return -1;
	}
	return cg_fd;
}

static void cleanup_cgroup(void)
{
	/* cgroup.procs 中的进程需先移出，否则 rmdir 失败 */
	int fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY);
	if (fd >= 0) {
		char pidbuf[32];
		int len = snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
		write(fd, pidbuf, len);
		close(fd);
	}
	rmdir(DEMO_CGROUP);
}

/* 双向 pipe 转发：client ↔ upstream，直到任一方 EOF */
static void pipe_loop(int client_fd, int upstream_fd)
{
	char buf[16384];
	int max_fd = (client_fd > upstream_fd ? client_fd : upstream_fd) + 1;

	while (!exiting) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(client_fd, &rfds);
		FD_SET(upstream_fd, &rfds);

		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		int n = select(max_fd, &rfds, NULL, NULL, &tv);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			continue;

		if (FD_ISSET(client_fd, &rfds)) {
			ssize_t r = read(client_fd, buf, sizeof(buf));
			if (r <= 0)
				break;
			write(upstream_fd, buf, r);
		}
		if (FD_ISSET(upstream_fd, &rfds)) {
			ssize_t r = read(upstream_fd, buf, sizeof(buf));
			if (r <= 0)
				break;
			write(client_fd, buf, r);
		}
	}
}

int main(int argc, char **argv)
{
	struct sidecar_bpf *skel = NULL;
	struct bpf_link *connect_link = NULL, *sockops_link = NULL, *skmsg_link = NULL;
	int listen_fd = -1, cg_fd = -1;
	int err = 0, map_fd, pid_map_fd;
	__u32 zero = 0, pid;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;  /* 不设 SA_RESTART，确保 accept/select 被中断返回 EINTR */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* ── 1. 设置 cgroup ── */
	cg_fd = setup_cgroup();
	if (cg_fd < 0) {
		err = 1;
		goto cleanup;
	}
	printf("[sidecar] cgroup ready: %s\n", DEMO_CGROUP);

	/* ── 2. 创建监听 socket ── */
	listen_fd = create_listening_socket();
	if (listen_fd < 0) {
		err = 1;
		goto cleanup;
	}
	printf("[sidecar] listening on 127.0.0.1:%d\n", SIDECAR_PORT);

	/* ── 3. 加载 BPF 骨架 ── */
	skel = sidecar_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "[sidecar] open/load skeleton failed\n");
		err = 1;
		goto cleanup;
	}

	/* ── 4. 写 sidecar PID 防递归 ── */
	pid_map_fd = bpf_map__fd(skel->maps.sidecar_pid_map);
	pid = getpid();
	if (bpf_map_update_elem(pid_map_fd, &zero, &pid, BPF_ANY) < 0) {
		fprintf(stderr, "[sidecar] write pid map: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	printf("[sidecar] pid=%d written to sidecar_pid_map\n", pid);

	/* ── 5. attach cgroup/connect4 + sockops ── */
	connect_link = bpf_program__attach_cgroup(skel->progs.hijack_connect, cg_fd);
	if (!connect_link) {
		fprintf(stderr, "[sidecar] attach connect4: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}
	sockops_link = bpf_program__attach_cgroup(skel->progs.bpf_sockops_handler, cg_fd);
	if (!sockops_link) {
		fprintf(stderr, "[sidecar] attach sockops: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* ── 6. attach sk_msg 到 SOCKHASH（本地流量加速） ── */
	skmsg_link = bpf_program__attach_sockmap(skel->progs.bpf_redir,
						bpf_map__fd(skel->maps.sock_ops_map));
	if (!skmsg_link) {
		fprintf(stderr, "[sidecar] attach sk_msg: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}
	printf("[sidecar] BPF attached (connect4 + sockops + sk_msg)\n");
	printf("[sidecar] proxying 127.0.0.1:%d -> 127.0.0.1:%d\n",
	       SIDECAR_PORT, SERVER_PORT);
	printf("[sidecar] test: curl http://127.0.0.1:%d/hello\n", SERVER_PORT);
	printf("[sidecar] Ctrl-C to stop\n\n");

	map_fd = bpf_map__fd(skel->maps.conn_map);

	/* ── 7. accept 循环 ── */
	while (!exiting) {
		struct sockaddr_in cli;
		socklen_t len = sizeof(cli);
		int cli_fd = accept(listen_fd, (struct sockaddr *)&cli, &len);
		if (cli_fd < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "[sidecar] accept: %s\n", strerror(errno));
			break;
		}

		/* 取客户端源 {ip,port} */
		struct conn_key ck = {
			.ip = cli.sin_addr.s_addr,
			.port = cli.sin_port,
			.pad = 0,
		};

		/* 查 conn_map 得原始目的 */
		struct orig_dst orig;
		if (bpf_map_lookup_elem(map_fd, &ck, &orig) < 0) {
			fprintf(stderr, "[sidecar] conn_map miss for %s:%d\n",
				inet_ntoa(cli.sin_addr), ntohs(cli.sin_port));
			close(cli_fd);
			continue;
		}
		bpf_map_delete_elem(map_fd, &ck);

		/* 连接原始目的（sidecar PID 被 BPF 跳过，不会递归） */
		int up_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (up_fd < 0) {
			fprintf(stderr, "[sidecar] upstream socket: %s\n", strerror(errno));
			close(cli_fd);
			continue;
		}
		struct sockaddr_in up_addr = {
			.sin_family = AF_INET,
			.sin_port = orig.port,
			.sin_addr.s_addr = orig.ip4,
		};
		if (connect(up_fd, (struct sockaddr *)&up_addr, sizeof(up_addr)) < 0) {
			fprintf(stderr, "[sidecar] upstream connect %s:%d: %s\n",
				inet_ntoa(up_addr.sin_addr), ntohs(up_addr.sin_port),
				strerror(errno));
			close(up_fd);
			close(cli_fd);
			continue;
		}

		printf("[sidecar] %s:%d -> orig %s:%d (fd %d<->%d)\n",
		       inet_ntoa(cli.sin_addr), ntohs(cli.sin_port),
		       inet_ntoa(up_addr.sin_addr), ntohs(up_addr.sin_port),
		       cli_fd, up_fd);

		/* 双向转发 */
		pipe_loop(cli_fd, up_fd);

		printf("[sidecar] connection closed (fd %d<->%d)\n", cli_fd, up_fd);
		close(up_fd);
		close(cli_fd);
	}

	err = 0;

cleanup:
	if (skmsg_link)
		bpf_link__destroy(skmsg_link);
	if (connect_link)
		bpf_link__destroy(connect_link);
	if (sockops_link)
		bpf_link__destroy(sockops_link);
	if (skel)
		sidecar_bpf__destroy(skel);
	if (listen_fd >= 0)
		close(listen_fd);
	if (cg_fd >= 0)
		close(cg_fd);
	cleanup_cgroup();
	return err < 0 ? -err : 0;
}
