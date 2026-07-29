// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 53-transparent-proxy-v4: 用户态 sidecar。
 *
 * v4 关键变化：端口一致（server 监听 :8080）。
 *   防回环由 sk_lookup 中的 PID 排除实现（sidecar PID 跳过）。
 *
 * 双钩子架构：
 *   - sk_lookup（netns）→ 入流量劫持 + PID 排除防回环
 *   - cgroup/connect4（cgroup）→ 出流量劫持（仅 server PID）
 *
 * sidecar 区分入/出流量（通过 conn_map 有无）：
 *   accept 后 getpeername → 查 conn_map[{peer_ip,peer_port}]
 *   - 有条目 → 出流量（server 被 connect4 改写到此）→ connect(orig_dst)
 *   - 无条目 → 入流量（外部 client 被 sk_lookup 重定向到此）→ connect(:8080)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
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

static int setup_cgroup(void)
{
	int cg_fd;

	if (mkdir(DEMO_CGROUP, 0755) < 0 && errno != EEXIST) {
		fprintf(stderr, "[sidecar] mkdir %s: %s\n", DEMO_CGROUP, strerror(errno));
		return -1;
	}

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
	/* 把 cgroup 内所有进程移回根 cgroup，否则 rmdir 失败 */
	FILE *f = fopen(DEMO_CGROUP "/cgroup.procs", "r");
	if (f) {
		int root_fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY);
		char line[32];
		while (fgets(line, sizeof(line), f)) {
			if (root_fd >= 0)
				write(root_fd, line, strlen(line));
		}
		if (root_fd >= 0)
			close(root_fd);
		fclose(f);
	}
	rmdir(DEMO_CGROUP);
}

/* 线程参数：每个连接一个 */
struct conn_ctx {
	int client_fd;
	int upstream_fd;
	char flow_type[16];
};

/* redir_stats 的 fd，用于统计线程 */
static int g_redir_stats_fd = -1;
static int g_ncpu = 1;

static void pipe_loop(int client_fd, int upstream_fd);

/* 线程入口：双向转发，结束后关闭 fd */
static void *handle_conn(void *arg)
{
	struct conn_ctx *ctx = arg;

	pipe_loop(ctx->client_fd, ctx->upstream_fd);

	printf("[sidecar] %s closed (fd %d<->%d)\n",
	       ctx->flow_type, ctx->client_fd, ctx->upstream_fd);
	close(ctx->upstream_fd);
	close(ctx->client_fd);
	free(ctx);
	return NULL;
}

/* 统计线程：每 5 秒读取 redir_stats PERCPU ARRAY 并打印 hit/miss */
static void *stats_thread(void *arg)
{
	(void)arg;
	while (!exiting) {
		for (int i = 0; i < 5 && !exiting; i++)
			sleep(1);
		if (exiting)
			break;

		if (g_redir_stats_fd < 0)
			continue;

		__u64 total_hit = 0, total_miss = 0;
		__u32 key;
		__u64 *vals;

		vals = calloc(g_ncpu, sizeof(__u64));
		if (!vals)
			continue;

		key = 0; /* hit */
		if (bpf_map_lookup_elem(g_redir_stats_fd, &key, vals) == 0)
			for (int i = 0; i < g_ncpu; i++)
				total_hit += vals[i];

		key = 1; /* miss */
		if (bpf_map_lookup_elem(g_redir_stats_fd, &key, vals) == 0)
			for (int i = 0; i < g_ncpu; i++)
				total_miss += vals[i];

		free(vals);

		printf("[sidecar] sk_msg stats: hit=%llu miss=%llu\n",
		       total_hit, total_miss);
	}
	return NULL;
}

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
	struct bpf_link *sk_lookup_link = NULL, *connect_link = NULL;
	struct bpf_link *sockops_link = NULL, *skmsg_link = NULL;
	int listen_fd = -1, cg_fd = -1, netns_fd = -1;
	int err = 0, conn_map_fd, sockmap_fd, pid_map_fd, srv_pid_map_fd;
	__u32 zero = 0, pid;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* ── 1. 设置 cgroup（仅 sidecar + server，不含 client） ── */
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

	/* ── 4. 写 sidecar listening socket fd 到 SOCKMAP（供 sk_lookup 用） ── */
	sockmap_fd = bpf_map__fd(skel->maps.sidecar_socks);
	{
		__u64 sock_val = (__u64)listen_fd;
		if (bpf_map_update_elem(sockmap_fd, &zero, &sock_val, BPF_ANY) < 0) {
			fprintf(stderr, "[sidecar] write sidecar_socks: %s\n", strerror(errno));
			err = 1;
			goto cleanup;
		}
	}
	printf("[sidecar] listen_fd=%d written to sidecar_socks SOCKMAP\n", listen_fd);

	/* ── 5. 写 sidecar PID 防递归 ── */
	pid_map_fd = bpf_map__fd(skel->maps.sidecar_pid_map);
	pid = getpid();
	if (bpf_map_update_elem(pid_map_fd, &zero, &pid, BPF_ANY) < 0) {
		fprintf(stderr, "[sidecar] write pid map: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	printf("[sidecar] pid=%d written to sidecar_pid_map\n", pid);

	/* ── 6. 写 server PID 到 server_pid_map（出流量劫持） ── */
	srv_pid_map_fd = bpf_map__fd(skel->maps.server_pid_map);
	if (argc > 1) {
		pid = atoi(argv[1]);
	} else {
		char *sp = getenv("SERVER_PID");
		pid = sp ? atoi(sp) : 0;
	}
	if (pid > 0) {
		if (bpf_map_update_elem(srv_pid_map_fd, &zero, &pid, BPF_ANY) < 0) {
			fprintf(stderr, "[sidecar] write server_pid_map: %s\n", strerror(errno));
			err = 1;
			goto cleanup;
		}
		printf("[sidecar] server_pid=%d (outbound hijack enabled)\n", pid);
		/* server 应已通过 --cgroup 自行加入 cgroup（在创建 listening
		 * socket 之前），此处不再代写，避免 socket cgroup 不一致。 */
	} else {
		printf("[sidecar] server_pid not set, outbound hijack disabled\n");
		printf("[sidecar] usage: %s <server_pid>\n", argv[0]);
	}

	/* ── 7. attach sk_lookup 到 netns（入流量劫持） ── */
	netns_fd = open("/proc/self/ns/net", O_RDONLY);
	if (netns_fd < 0) {
		fprintf(stderr, "[sidecar] open netns: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}
	sk_lookup_link = bpf_program__attach_netns(skel->progs.inbound_lookup, netns_fd);
	if (!sk_lookup_link) {
		fprintf(stderr, "[sidecar] attach sk_lookup: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}
	printf("[sidecar] sk_lookup attached to netns (inbound :%d -> sidecar)\n", VIRTUAL_PORT);

	/* ── 8. attach connect4 + sockops 到 cgroup（出流量劫持 + 桥接） ── */
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

	/* ── 9. attach sk_msg 到 SOCKHASH（本地加速） ── */
	skmsg_link = bpf_program__attach_sockmap(skel->progs.bpf_redir,
						bpf_map__fd(skel->maps.sock_ops_map));
	if (!skmsg_link) {
		fprintf(stderr, "[sidecar] attach sk_msg: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	printf("[sidecar] BPF attached (sk_lookup + connect4 + sockops + sk_msg)\n");
	printf("[sidecar] inbound: :%d -> sidecar -> :%d\n", VIRTUAL_PORT, SERVER_PORT);
	if (pid > 0)
		printf("[sidecar] outbound: server -> sidecar -> orig dst\n");
	printf("[sidecar] test: curl http://127.0.0.1:%d/hello  (inbound, no cgroup needed)\n", VIRTUAL_PORT);
	if (pid > 0)
		printf("[sidecar] test: curl http://127.0.0.1:%d/outbound  (outbound)\n", VIRTUAL_PORT);
	printf("[sidecar] Ctrl-C to stop\n\n");

	conn_map_fd = bpf_map__fd(skel->maps.conn_map);

	/* ── 10a. 启动统计线程（每 5 秒打印 sk_msg redirect hit/miss） ── */
	g_redir_stats_fd = bpf_map__fd(skel->maps.redir_stats);
	g_ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (g_ncpu < 1)
		g_ncpu = 1;
	{
		pthread_t stats_tid;
		if (pthread_create(&stats_tid, NULL, stats_thread, NULL) == 0)
			pthread_detach(stats_tid);
	}

	/* ── 10b. accept 循环 ── */
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

		struct conn_key ck = {
			.ip = cli.sin_addr.s_addr,
			.port = cli.sin_port,
			.pad = 0,
		};

		struct orig_dst orig;
		struct sockaddr_in up_addr;
		const char *flow_type;
		int up_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (up_fd < 0) {
			fprintf(stderr, "[sidecar] upstream socket: %s\n", strerror(errno));
			close(cli_fd);
			continue;
		}

		/* 区分入/出流量：查 conn_map */
		if (bpf_map_lookup_elem(conn_map_fd, &ck, &orig) == 0) {
			/* 出流量：server 的出连接被 connect4 改写到此 */
			bpf_map_delete_elem(conn_map_fd, &ck);
			up_addr.sin_family = AF_INET;
			up_addr.sin_port = orig.port;
			up_addr.sin_addr.s_addr = orig.ip4;
			flow_type = "outbound";
		} else {
			/* 入流量：外部 client 被 sk_lookup 重定向到此 → 回源到 :8080
			 * v4 端口一致：server 也监听 :8080，靠 sk_lookup PID 排除防回环 */
			up_addr.sin_family = AF_INET;
			up_addr.sin_port = htons(SERVER_PORT);
			up_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
			flow_type = "inbound";
		}

		if (connect(up_fd, (struct sockaddr *)&up_addr, sizeof(up_addr)) < 0) {
			fprintf(stderr, "[sidecar] upstream connect %s:%d: %s\n",
				inet_ntoa(up_addr.sin_addr), ntohs(up_addr.sin_port),
				strerror(errno));
			close(up_fd);
			close(cli_fd);
			continue;
		}

		struct in_addr orig_ip = { .s_addr = up_addr.sin_addr.s_addr };
		printf("[sidecar] %s: %s:%d -> %s:%d (fd %d<->%d)\n",
		       flow_type,
		       inet_ntoa(cli.sin_addr), ntohs(cli.sin_port),
		       inet_ntoa(orig_ip), ntohs(up_addr.sin_port),
		       cli_fd, up_fd);

		/* 创建线程处理双向转发，主线程继续 accept */
		struct conn_ctx *cctx = malloc(sizeof(*cctx));
		if (!cctx) {
			fprintf(stderr, "[sidecar] malloc failed\n");
			close(up_fd);
			close(cli_fd);
			continue;
		}
		cctx->client_fd = cli_fd;
		cctx->upstream_fd = up_fd;
		strncpy(cctx->flow_type, flow_type, sizeof(cctx->flow_type) - 1);
		cctx->flow_type[sizeof(cctx->flow_type) - 1] = '\0';

		pthread_t tid;
		if (pthread_create(&tid, NULL, handle_conn, cctx) != 0) {
			fprintf(stderr, "[sidecar] pthread_create: %s\n", strerror(errno));
			free(cctx);
			close(up_fd);
			close(cli_fd);
			continue;
		}
		pthread_detach(tid);
	}

	err = 0;

cleanup:
	if (skmsg_link)
		bpf_link__destroy(skmsg_link);
	if (sockops_link)
		bpf_link__destroy(sockops_link);
	if (connect_link)
		bpf_link__destroy(connect_link);
	if (sk_lookup_link)
		bpf_link__destroy(sk_lookup_link);
	if (skel)
		sidecar_bpf__destroy(skel);
	if (listen_fd >= 0)
		close(listen_fd);
	if (netns_fd >= 0)
		close(netns_fd);
	if (cg_fd >= 0)
		close(cg_fd);
	cleanup_cgroup();
	return err < 0 ? -err : 0;
}
