// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 77-sock-addr-monitor: 用户态加载器 + 测试。
 *
 * 流程：
 *   1. 创建专用子 cgroup
 *   2. 加载 17 个 BPF 程序，全部 attach 到 cgroup
 *   3. fork 子进程进入 cgroup，执行 socket 操作触发所有 hook：
 *      - TCP IPv4: bind + listen + connect + getsockname + getpeername
 *      - UDP IPv4: sendmsg + recvmsg + getsockname
 *      - TCP IPv6: 同上
 *      - UDP IPv6: 同上
 *      - Unix socket: connect + sendmsg + recvmsg + getpeername + getsockname
 *   4. 父进程消费 ringbuf，打印事件
 *   5. 清理
 *
 * 用法：sudo ./sock-addr-monitor
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sock-addr-monitor.h"
#include "sock-addr-monitor.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* 操作名称 */
static const char *op_str(__u8 op)
{
	switch (op) {
	case OP_BIND4:            return "BIND4       ";
	case OP_BIND6:            return "BIND6       ";
	case OP_CONNECT4:         return "CONNECT4    ";
	case OP_CONNECT6:         return "CONNECT6    ";
	case OP_CONNECT_UNIX:     return "CONNECT_UNIX";
	case OP_SENDMSG4:         return "SENDMSG4    ";
	case OP_SENDMSG6:         return "SENDMSG6    ";
	case OP_SENDMSG_UNIX:     return "SENDMSG_UNIX";
	case OP_RECVMSG4:         return "RECVMSG4    ";
	case OP_RECVMSG6:         return "RECVMSG6    ";
	case OP_RECVMSG_UNIX:     return "RECVMSG_UNIX";
	case OP_GETPEERNAME4:     return "GETPEERNAME4";
	case OP_GETPEERNAME6:     return "GETPEERNAME6";
	case OP_GETPEERNAME_UNIX: return "GETPEER_UNX ";
	case OP_GETSOCKNAME4:     return "GETSOCKNAME4";
	case OP_GETSOCKNAME6:     return "GETSOCKNAME6";
	case OP_GETSOCKNAME_UNIX:  return "GETSOCK_UNX ";
	default:                  return "UNKNOWN     ";
	}
}

static const char *family_str(__u32 f)
{
	switch (f) {
	case 1:  return "AF_UNIX ";
	case 2:  return "AF_INET ";
	case 10: return "AF_INET6";
	default: return "other";
	}
}

static const char *type_str(__u32 t)
{
	switch (t) {
	case 1: return "STREAM";
	case 2: return "DGRAM ";
	default: return "other ";
	}
}

static const char *proto_str(__u32 p)
{
	switch (p) {
	case 6:  return "TCP";
	case 17: return "UDP";
	default: return "-  ";
	}
}

static void ip4_str(__u32 ip4, char *buf, size_t sz)
{
	struct in_addr a = { .s_addr = ip4 };
	snprintf(buf, sz, "%s", inet_ntoa(a));
}

static void ip6_str(const __u32 ip6[4], char *buf, size_t sz)
{
	const struct in6_addr *a = (const struct in6_addr *)ip6;
	inet_ntop(AF_INET6, a, buf, sz);
}

/* ringbuf 回调 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	char ipbuf[64];

	if (e->user_family == 2)
		ip4_str(e->ip4, ipbuf, sizeof(ipbuf));
	else if (e->user_family == 10)
		ip6_str(e->ip6, ipbuf, sizeof(ipbuf));
	else
		snprintf(ipbuf, sizeof(ipbuf), "-");

	printf("  [%s] family=%-8s type=%-6s proto=%-3s port=%-6u ip=%s  pid=%u\n",
	       op_str(e->op),
	       family_str(e->user_family),
	       type_str(e->sock_type),
	       proto_str(e->protocol),
	       e->port,
	       ipbuf,
	       e->pid);
	return 0;
}

	/* ── 子进程：进入 cgroup 后执行 socket 操作 ── */
static void run_in_cgroup(void)
{
	char buf[32];
	int fd;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 }; /* 1s recv timeout */

	/* 进入 cgroup */
	fd = open(DEMO_CGROUP "/cgroup.procs", O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "\t  [child] open cgroup.procs: %s\n", strerror(errno));
		_exit(1);
	}
	snprintf(buf, sizeof(buf), "%d", getpid());
	write(fd, buf, strlen(buf));
	close(fd);
	usleep(100000);
	fprintf(stderr, "\t  [child] moved into cgroup (pid=%d)\n\n", getpid());

	/* ── TCP IPv4 ── */
	fprintf(stderr, "\t  --- TCP IPv4 ---\n");
	int s4 = socket(AF_INET, SOCK_STREAM, 0);
	int c4 = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in srv4 = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	bind(s4, (struct sockaddr *)&srv4, sizeof(srv4));
	listen(s4, 1);

	struct sockaddr_in actual;
	socklen_t alen = sizeof(actual);
	getsockname(s4, (struct sockaddr *)&actual, &alen);

	struct sockaddr_in dst4 = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = actual.sin_port };
	connect(c4, (struct sockaddr *)&dst4, sizeof(dst4));
	getpeername(c4, (struct sockaddr *)&actual, &alen);
	getsockname(c4, (struct sockaddr *)&actual, &alen);
	close(s4); close(c4);
	sleep(2);
	/* ── UDP IPv4 ── */
	fprintf(stderr, "\t  --- UDP IPv4 ---\n");
	int u4s = socket(AF_INET, SOCK_DGRAM, 0);  /* sender */
	int u4r = socket(AF_INET, SOCK_DGRAM, 0);  /* receiver */
	setsockopt(u4r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* 先 bind receiver，再发送给它 */
	struct sockaddr_in u4bind = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	bind(u4r, (struct sockaddr *)&u4bind, sizeof(u4bind));
	getsockname(u4r, (struct sockaddr *)&actual, &alen);

	/* sendmsg 到一个无人监听的端口（触发 sendmsg4） */
	struct sockaddr_in udp_dst = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(9999) };
	sendto(u4s, "hi", 2, 0, (struct sockaddr *)&udp_dst, sizeof(udp_dst));

	/* sendmsg 到 receiver（触发 sendmsg4），receiver recvfrom（触发 recvmsg4） */
	udp_dst.sin_port = actual.sin_port;
	sendto(u4s, "hi", 2, 0, (struct sockaddr *)&udp_dst, sizeof(udp_dst));
	char rbuf[16];
	struct sockaddr_in src4;
	socklen_t src4len = sizeof(src4);
	recvfrom(u4r, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&src4, &src4len);
	close(u4s); close(u4r);
	sleep(2);

	/* ── TCP IPv6 ── */
	fprintf(stderr, "\t  --- TCP IPv6 ---\n");
	int s6 = socket(AF_INET6, SOCK_STREAM, 0);
	int c6 = socket(AF_INET6, SOCK_STREAM, 0);

	struct sockaddr_in6 srv6 = { .sin6_family = AF_INET6 };
	srv6.sin6_addr = in6addr_loopback;
	bind(s6, (struct sockaddr *)&srv6, sizeof(srv6));
	listen(s6, 1);
	getsockname(s6, (struct sockaddr *)&actual, &alen);

	struct sockaddr_in6 dst6 = { .sin6_family = AF_INET6 };
	dst6.sin6_addr = in6addr_loopback;
	memcpy(&dst6.sin6_port, &actual.sin_port, 2);
	connect(c6, (struct sockaddr *)&dst6, sizeof(dst6));
	getpeername(c6, (struct sockaddr *)&actual, &alen);
	getsockname(c6, (struct sockaddr *)&actual, &alen);
	close(s6); close(c6);
	sleep(2);

	/* ── UDP IPv6 ── */
	fprintf(stderr, "\t  --- UDP IPv6 ---\n");
	int u6s = socket(AF_INET6, SOCK_DGRAM, 0);  /* sender */
	int u6r = socket(AF_INET6, SOCK_DGRAM, 0);  /* receiver */
	setsockopt(u6r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct sockaddr_in6 u6bind = { .sin6_family = AF_INET6 };
	u6bind.sin6_addr = in6addr_loopback;
	bind(u6r, (struct sockaddr *)&u6bind, sizeof(u6bind));
	getsockname(u6r, (struct sockaddr *)&actual, &alen);

	struct sockaddr_in6 u6dst = { .sin6_family = AF_INET6 };
	u6dst.sin6_addr = in6addr_loopback;
	u6dst.sin6_port = htons(9999);
	sendto(u6s, "hi", 2, 0, (struct sockaddr *)&u6dst, sizeof(u6dst));

	memcpy(&u6dst.sin6_port, &actual.sin_port, 2);
	sendto(u6s, "hi", 2, 0, (struct sockaddr *)&u6dst, sizeof(u6dst));
	struct sockaddr_in6 src6;
	socklen_t src6len = sizeof(src6);
	recvfrom(u6r, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&src6, &src6len);
	close(u6s); close(u6r);
	sleep(2);

	/* ── Unix socket ── */
	fprintf(stderr, "\t  --- Unix socket ---\n");
	const char *sockpath = "/tmp/cg-sock-monitor-unix";
	unlink(sockpath);

	int us = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un uaddr = { .sun_family = AF_UNIX };
	strncpy(uaddr.sun_path, sockpath, sizeof(uaddr.sun_path) - 1);
	bind(us, (struct sockaddr *)&uaddr, sizeof(uaddr));
	listen(us, 1);

	int uc = socket(AF_UNIX, SOCK_STREAM, 0);
	/* 显式 bind 到 abstract name，使 addr != NULL，
	 * 否则 getsockname 不会触发 BPF hook（unix_getname 跳过 addr==NULL 的 socket） */
	struct sockaddr_un ubindc = { .sun_family = AF_UNIX };
	ubindc.sun_path[0] = 0;  /* abstract namespace 第一个字节为 0 */
	ubindc.sun_path[1] = 'c';
	bind(uc, (struct sockaddr *)&ubindc, sizeof(ubindc));

	struct sockaddr_un udst = { .sun_family = AF_UNIX };
	strncpy(udst.sun_path, sockpath, sizeof(udst.sun_path) - 1);
	connect(uc, (struct sockaddr *)&udst, sizeof(udst));
	getpeername(uc, (struct sockaddr *)&uaddr, &(socklen_t){sizeof(uaddr)});
	getsockname(uc, (struct sockaddr *)&uaddr, &(socklen_t){sizeof(uaddr)});
	close(us); close(uc);
	unlink(sockpath);  /* 清理 STREAM socket 文件，供 DGRAM 复用路径 */
	sleep(2);

	/* Unix DGRAM */
	fprintf(stderr, "\t  --- Unix DGRAM ---\n");
	int ud = socket(AF_UNIX, SOCK_DGRAM, 0);
	/* 给 sender 也 bind 到 abstract name（使 getsockname 能触发 BPF hook） */
	struct sockaddr_un udbind = { .sun_family = AF_UNIX };
	udbind.sun_path[0] = 0;
	udbind.sun_path[1] = 'd';
	bind(ud, (struct sockaddr *)&udbind, sizeof(udbind));

	int ur = socket(AF_UNIX, SOCK_DGRAM, 0);
	setsockopt(ur, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	struct sockaddr_un ubindun = { .sun_family = AF_UNIX };
	strncpy(ubindun.sun_path, sockpath, sizeof(ubindun.sun_path) - 1);
	bind(ur, (struct sockaddr *)&ubindun, sizeof(ubindun));

	struct sockaddr_un udest = { .sun_family = AF_UNIX };
	strncpy(udest.sun_path, sockpath, sizeof(udest.sun_path) - 1);
	sendto(ud, "hi", 2, 0, (struct sockaddr *)&udest, sizeof(udest));
	struct sockaddr_un srcun;
	socklen_t srcunlen = sizeof(srcun);
	recvfrom(ur, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&srcun, &srcunlen);
	getsockname(ur, (struct sockaddr *)&uaddr, &(socklen_t){sizeof(uaddr)});
	close(ud); close(ur);
	unlink(sockpath);
	sleep(2);

	fprintf(stderr, "\t  [child] All socket operations done.\n\n");
	usleep(500000);  /* 给父进程时间 poll 剩余 ringbuf 事件 */
	_exit(0);
}

/* attach 一个程序，返回 link，失败返回 NULL */
static struct bpf_link *try_attach(struct bpf_program *prog, int cg_fd)
{
	struct bpf_link *link = bpf_program__attach_cgroup(prog, cg_fd);
	if (!link)
		fprintf(stderr, "  attach %s failed: %s\n",
			bpf_program__name(prog), strerror(errno));
	return link;
}

int main(int argc, char **argv)
{
	struct sock_addr_monitor_bpf *skel;
	struct bpf_link *links[17] = {};
	struct ring_buffer *ringbuf = NULL;
	int err = 0, cg_fd = -1, nlinks = 0;
	pid_t child;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, SIG_IGN);
	libbpf_set_print(libbpf_print_fn);

	/* 1. 创建 cgroup */
	if (mkdir(DEMO_CGROUP, 0755) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir %s: %s\n", DEMO_CGROUP, strerror(errno));
		return 1;
	}
	cg_fd = open(DEMO_CGROUP, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "open %s: %s\n", DEMO_CGROUP, strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 2. 加载 skeleton */
	skel = sock_addr_monitor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* 3. attach 全部 17 个程序 */
	/* bind */
	links[nlinks++] = try_attach(skel->progs.bind4_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.bind6_hook, cg_fd);
	/* connect */
	links[nlinks++] = try_attach(skel->progs.connect4_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.connect6_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.connect_unix_hook, cg_fd);
	/* sendmsg */
	links[nlinks++] = try_attach(skel->progs.sendmsg4_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.sendmsg6_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.sendmsg_unix_hook, cg_fd);
	/* recvmsg */
	links[nlinks++] = try_attach(skel->progs.recvmsg4_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.recvmsg6_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.recvmsg_unix_hook, cg_fd);
	/* getpeername */
	links[nlinks++] = try_attach(skel->progs.getpeername4_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.getpeername6_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.getpeername_unix_hook, cg_fd);
	/* getsockname */
	links[nlinks++] = try_attach(skel->progs.getsockname4_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.getsockname6_hook, cg_fd);
	links[nlinks++] = try_attach(skel->progs.getsockname_unix_hook, cg_fd);

	/* 检查是否有 attach 失败 */
	int failed = 0;
	for (int i = 0; i < nlinks; i++) {
		if (!links[i]) {
			failed++;
			err = 1;
		}
	}
	if (failed) {
		fprintf(stderr, "%d program(s) failed to attach\n", failed);
		goto cleanup;
	}

	/* 4. 设置 ringbuf */
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	printf("BPF sock_addr monitor attached to %s\n", DEMO_CGROUP);
	printf("  %d programs attached (bind×2, connect×3, sendmsg×3, recvmsg×3, getpeername×3, getsockname×3)\n\n",
	       nlinks);

	/* 5. fork 子进程测试 */
	child = fork();
	if (child == 0) {
		run_in_cgroup();
		_exit(0);
	} else if (child < 0) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 父进程：消费 ringbuf，等待子进程完成 */
	printf("BPF events:\n");
	int status;
	while (waitpid(child, &status, WNOHANG) == 0) {
		ring_buffer__poll(ringbuf, 50);
	}
	/* 排空剩余事件 */
	for (int i = 0; i < 30; i++) {
		if (ring_buffer__poll(ringbuf, 200) <= 0)
			break;
	}

	printf("\nAll socket operations demonstrated.\n");

cleanup:
	ring_buffer__free(ringbuf);
	for (int i = 0; i < nlinks; i++) {
		if (links[i])
			bpf_link__destroy(links[i]);
	}
	if (skel)
		sock_addr_monitor_bpf__destroy(skel);
	if (cg_fd >= 0)
		close(cg_fd);
	rmdir(DEMO_CGROUP);
	return err < 0 ? -err : 0;
}
