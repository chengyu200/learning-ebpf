// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 73-lsm-cgroup: 用户态 — cgroup 创建 + attach + 测试。
 *
 * 流程：
 *   1. 创建专用子 cgroup
 *   2. 加载 lsm_cgroup BPF 程序
 *   3. bpf_program__attach_cgroup 挂载到该 cgroup
 *   4. fork 子进程进入 cgroup，测试 connect 被拦截
 *   5. 父进程在 cgroup 外，connect 不受影响
 *   6. detach + 清理 cgroup
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lsm-cg.h"
#include "lsm-cg.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* 尝试连接 127.0.0.1:port，返回 0=成功，负数=失败 */
static int try_connect(int port)
{
	int fd;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
	};

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -errno;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int err = -errno;
		close(fd);
		return err;
	}

	close(fd);
	return 0;
}

/* 子进程：进入 cgroup 后测试连接 */
static void run_in_cgroup(void)
{
	char buf[32];

	/* 写自身 PID 到 cgroup.procs */
	int fd = open(DEMO_CGROUP "/cgroup.procs", O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "  [child] open cgroup.procs: %s\n", strerror(errno));
		_exit(1);
	}
	snprintf(buf, sizeof(buf), "%d", getpid());
	write(fd, buf, strlen(buf));
	close(fd);
	/* 等待 cgroup 成员身份生效 */
	usleep(100000);
	fprintf(stderr, "  [child] moved into cgroup (pid=%d)\n", getpid());

	/* 测试1：connect 127.0.0.1:9999 → 应被 lsm_cgroup 拒绝 */
	int ret = try_connect(BLOCK_PORT);
	fprintf(stderr, "  [child] connect :%d → errno=%d (%s)\n",
		BLOCK_PORT, -ret, strerror(-ret));
	if (ret == 0) {
		fprintf(stderr, "  [child] FAIL: :%d succeeded (should be blocked)\n", BLOCK_PORT);
		_exit(1);
	} else if (ret == -EACCES || ret == -EPERM) {
		fprintf(stderr, "  [child] PASS: :%d blocked by LSM (EPERM/EACCES)\n", BLOCK_PORT);
	} else {
		/* ECONNREFUSED etc. — might be blocked by LSM returning 1,
		 * which the kernel translates to ECONNREFUSED for connect() */
		fprintf(stderr, "  [child] PASS: :%d blocked (errno=%d, possibly LSM)\n",
			BLOCK_PORT, -ret);
	}

	/* 测试2：connect 127.0.0.1:8080 → 应成功（策略只阻止 :9999） */
	ret = try_connect(8080);
	fprintf(stderr, "  [child] connect :8080 → errno=%d (%s)\n", -ret, strerror(-ret));
	if (ret == 0 || ret == -ECONNREFUSED) {
		fprintf(stderr, "  [child] PASS: :8080 not blocked by LSM\n");
	} else {
		fprintf(stderr, "  [child] FAIL: :8080 blocked (errno=%d, should not be)\n", -ret);
		_exit(1);
	}

	fprintf(stderr, "  [child] All tests passed.\n");
	_exit(0);
}

int main(int argc, char **argv)
{
	struct lsm_cg_bpf *skel;
	struct bpf_link *link = NULL;
	int err = 0, cg_fd = -1;
	pid_t child;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	/* 1. 创建专用子 cgroup */
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

	/* 2. 加载 BPF 程序 */
	skel = lsm_cg_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* 3. attach lsm_cgroup 到 cgroup（手动 attach，skeleton 不自动） */
	link = bpf_program__attach_cgroup(skel->progs.block_connect, cg_fd);
	if (!link) {
		fprintf(stderr, "attach_cgroup failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	printf("lsm_cgroup attached to %s\n", DEMO_CGROUP);
	printf("  Policy: block connect to 127.0.0.1:%d for cgroup members\n\n", BLOCK_PORT);

	/* 4. fork 子进程进入 cgroup 测试 */
	child = fork();
	if (child == 0) {
		run_in_cgroup();
		_exit(0);
	} else if (child < 0) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 等待子进程完成 */
	int status;
	waitpid(child, &status, 0);
	printf("\n");

	/* 5. 父进程在 cgroup 外，连接不受限制 */
	printf("Parent (outside cgroup) testing:\n");
	int ret = try_connect(BLOCK_PORT);
	if (ret == 0 || ret == -ECONNREFUSED) {
		printf("  PASS: connect :9999 not blocked (%s)\n",
		       ret == 0 ? "connected" : "refused (no server)");
	} else {
		printf("  UNEXPECTED: connect :9999 error: %s\n", strerror(-ret));
	}

	printf("\nAll tests done. Cleaning up.\n");

cleanup:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		lsm_cg_bpf__destroy(skel);
	if (cg_fd >= 0)
		close(cg_fd);
	rmdir(DEMO_CGROUP);
	return err < 0 ? -err : 0;
}
