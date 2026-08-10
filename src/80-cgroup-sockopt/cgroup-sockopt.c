// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 80-cgroup-sockopt: 用户态加载器 + 测试。
 *
 * 流程：
 *   1. 创建专用子 cgroup
 *   2. 加载 2 个 BPF 程序，attach 到 cgroup
 *   3. fork 子进程进入 cgroup，测试 socket 选项操作：
 *      - setsockopt(SO_REUSEADDR) → EPERM（被 BPF 拒绝）
 *      - setsockopt(SO_KEEPALIVE) → 成功（BPF 放行）
 *      - getsockopt(SO_TYPE)      → 成功（审计记录）
 *      - getsockopt(IP_TTL)       → 返回 64（BPF 改写）
 *   4. 父进程消费 ringbuf，打印事件
 *   5. 清理
 *
 * 用法：sudo ./cgroup-sockopt
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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup-sockopt.h"
#include "cgroup-sockopt.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* 选项名称可读字符串 */
static const char *optname_str(__s32 level, __s32 optname)
{
	if (level == SOL_SOCKET) {
		switch (optname) {
		case SO_REUSEADDR: return "SO_REUSEADDR";
		case SO_KEEPALIVE: return "SO_KEEPALIVE";
		case SO_TYPE:      return "SO_TYPE";
		default:           return "?";
		}
	}
	if (level == SOL_IP) {
		switch (optname) {
		case IP_TTL:       return "IP_TTL";
		default:           return "?";
		}
	}
	return "?";
}

static const char *decision_str(__u8 d)
{
	switch (d) {
	case DEC_ALLOWED:   return "allowed  ";
	case DEC_BLOCKED:   return "BLOCKED  ";
	case DEC_REWRITTEN: return "rewritten";
	default:            return "?        ";
	}
}

/* ringbuf 回调 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	const char *op_str = (e->op == OP_SETSOCKOPT) ? "SET" : "GET";

	if (e->decision == DEC_REWRITTEN)
		printf("\t  [%s] level=%d optname=%d (%-14s) optlen=%d  %s→%d  pid=%u\n",
		       op_str, e->level, e->optname, optname_str(e->level, e->optname),
		       e->optlen, decision_str(e->decision), e->rewritten_val, e->pid);
	else
		printf("\t  [%s] level=%d optname=%d (%-14s) optlen=%d  %s  pid=%u\n",
		       op_str, e->level, e->optname, optname_str(e->level, e->optname),
		       e->optlen, decision_str(e->decision), e->pid);
	return 0;
}

/* ── 子进程：进入 cgroup 后执行 socket 选项测试 ── */
static void run_in_cgroup(void)
{
	char buf[32];
	int fd, ret, val;
	socklen_t len;

	/* 进入 cgroup */
	fd = open(DEMO_CGROUP "/cgroup.procs", O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "  [child] open cgroup.procs: %s\n", strerror(errno));
		_exit(1);
	}
	snprintf(buf, sizeof(buf), "%d", getpid());
	write(fd, buf, strlen(buf));
	close(fd);
	usleep(100000);
	fprintf(stderr, "  [child] moved into cgroup (pid=%d)\n\n", getpid());

	/* 创建测试 socket */
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "  [child] socket: %s\n", strerror(errno));
		_exit(1);
	}

	/* 测试 1：setsockopt SO_REUSEADDR → 应被拒绝（EPERM） */
	fprintf(stderr, "  [child] test 1: setsockopt SO_REUSEADDR...\n");
	val = 1;
	errno = 0;
	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	fprintf(stderr, "  [child]   ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
	if (ret < 0 && (errno == EPERM || errno == EACCES)) {
		fprintf(stderr, "  [child] PASS: SO_REUSEADDR blocked (%s)\n\n", strerror(errno));
	} else {
		fprintf(stderr, "  [child] FAIL: SO_REUSEADDR should be blocked\n\n");
	}

	/* 测试 2：setsockopt SO_KEEPALIVE → 应成功（放行） */
	fprintf(stderr, "  [child] test 2: setsockopt SO_KEEPALIVE...\n");
	val = 1;
	errno = 0;
	ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
	fprintf(stderr, "  [child]   ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
	if (ret == 0) {
		fprintf(stderr, "  [child] PASS: SO_KEEPALIVE allowed (OK)\n\n");
	} else {
		fprintf(stderr, "  [child] FAIL: SO_KEEPALIVE should succeed\n\n");
	}

	/* 测试 3：getsockopt SO_TYPE → 应成功（审计记录） */
	fprintf(stderr, "  [child] test 3: getsockopt SO_TYPE...\n");
	val = 0;
	len = sizeof(val);
	errno = 0;
	ret = getsockopt(sock, SOL_SOCKET, SO_TYPE, &val, &len);
	fprintf(stderr, "  [child]   ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
	if (ret == 0) {
		fprintf(stderr, "  [child] PASS: SO_TYPE = %d (allowed)\n\n", val);
	} else {
		fprintf(stderr, "  [child] FAIL: getsockopt SO_TYPE\n\n");
	}

	/* 测试 4：getsockopt IP_TTL → 应返回 64（BPF 改写） */
	fprintf(stderr, "  [child] test 4: getsockopt IP_TTL...\n");
	val = 0;
	len = sizeof(val);
	errno = 0;
	ret = getsockopt(sock, SOL_IP, IP_TTL, &val, &len);
	fprintf(stderr, "  [child]   ret=%d errno=%d val=%d (%s)\n", ret, errno, val, strerror(errno));
	if (ret == 0 && val == 64) {
		fprintf(stderr, "  [child] PASS: IP_TTL = %d (rewritten by BPF)\n\n", val);
	} else if (ret == 0) {
		fprintf(stderr, "  [child] FAIL: IP_TTL = %d (expected 64)\n\n", val);
	} else {
		fprintf(stderr, "  [child] FAIL: getsockopt IP_TTL\n\n");
	}

	close(sock);
	fprintf(stderr, "  [child] All tests done.\n");
	usleep(500000);
	_exit(0);
}

int main(int argc, char **argv)
{
	struct cgroup_sockopt_bpf *skel;
	struct bpf_link *set_link = NULL, *get_link = NULL;
	struct ring_buffer *ringbuf = NULL;
	int err = 0, cg_fd = -1;
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
	skel = cgroup_sockopt_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* 3. attach 两个程序 */
	set_link = bpf_program__attach_cgroup(skel->progs.cg_setsockopt, cg_fd);
	if (!set_link) {
		fprintf(stderr, "attach setsockopt failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	get_link = bpf_program__attach_cgroup(skel->progs.cg_getsockopt, cg_fd);
	if (!get_link) {
		fprintf(stderr, "attach getsockopt failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 4. 设置 ringbuf */
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	printf("BPF cgroup/sockopt firewall attached to %s\n", DEMO_CGROUP);
	printf("  setsockopt: BLOCK SO_REUSEADDR, AUDIT all others\n");
	printf("  getsockopt: AUDIT all, REWRITE IP_TTL→64\n\n");

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
	printf("Child (in cgroup) testing:\n");
	int status;
	while (waitpid(child, &status, WNOHANG) == 0) {
		ring_buffer__poll(ringbuf, 50);
	}
	/* 排空剩余事件 */
	for (int i = 0; i < 20; i++) {
		if (ring_buffer__poll(ringbuf, 100) <= 0)
			break;
	}

	printf("\nBPF events (above) match the test results.\n");

cleanup:
	ring_buffer__free(ringbuf);
	if (get_link)
		bpf_link__destroy(get_link);
	if (set_link)
		bpf_link__destroy(set_link);
	if (skel)
		cgroup_sockopt_bpf__destroy(skel);
	if (cg_fd >= 0)
		close(cg_fd);
	rmdir(DEMO_CGROUP);
	return err < 0 ? -err : 0;
}
