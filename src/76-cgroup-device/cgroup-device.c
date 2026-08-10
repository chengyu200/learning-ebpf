// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 76-cgroup-device: 用户态加载器 + 测试。
 *
 * 流程：
 *   1. 创建专用子 cgroup
 *   2. 加载 BPF 程序
 *   3. 用 hash map 配置设备白名单：
 *      - /dev/null     (1:3)  → mknod|read|write
 *      - /dev/zero     (1:5)  → mknod|read|write
 *      - /dev/urandom  (1:9)  → read
 *   4. bpf_program__attach_cgroup 挂载到 cgroup
 *   5. fork 子进程进入 cgroup，测试设备访问：
 *      - open /dev/zero + read  → ALLOWED（白名单允许 read）
 *      - open /dev/mem  + read  → DENIED（不在白名单）
 *      - mknod testdev          → DENIED（不在白名单）
 *   6. 父进程消费 ringbuf，打印设备访问决策
 *   7. 清理 cgroup
 *
 * 用法：
 *   sudo ./cgroup-device
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
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup-device.h"
#include "cgroup-device.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* 设备白名单条目 */
struct allow_entry {
	const char *name;
	__u32 major;
	__u32 minor;
	__u32 allow_mask;
};

static const struct allow_entry allowlist[] = {
	{ "/dev/null",     1, 3, BPF_DEVCG_ACC_MKNOD | BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE },
	{ "/dev/zero",     1, 5, BPF_DEVCG_ACC_MKNOD | BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE },
	{ "/dev/urandom",  1, 9, BPF_DEVCG_ACC_READ },
};

#define NUM_ALLOW (sizeof(allowlist) / sizeof(allowlist[0]))

static const char *access_str(__u32 acc)
{
	static char buf[32];
	buf[0] = '\0';
	if (acc & BPF_DEVCG_ACC_MKNOD) strcat(buf, "mknod|");
	if (acc & BPF_DEVCG_ACC_READ)  strcat(buf, "read|");
	if (acc & BPF_DEVCG_ACC_WRITE) strcat(buf, "write|");
	int len = strlen(buf);
	if (len > 0 && buf[len - 1] == '|')
		buf[len - 1] = '\0';
	return buf;
}

static const char *dev_type_str(__u8 dt)
{
	if (dt == BPF_DEVCG_DEV_BLOCK) return "block";
	if (dt == BPF_DEVCG_DEV_CHAR)  return "char";
	return "unknown";
}

/* ringbuf 回调 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	printf("  [%s] %-5s %u:%u  access=%-12s  pid=%u  comm=%s\n",
	       e->allowed ? "ALLOW" : "DENY",
	       dev_type_str(e->dev_type),
	       e->major, e->minor,
	       access_str(e->access),
	       e->pid, e->comm);
	return 0;
}

/* 子进程：进入 cgroup 后测试设备访问 */
static void run_in_cgroup(void)
{
	char buf[32];
	int fd, ret;

	/* 写自身 PID 到 cgroup.procs */
	fd = open(DEMO_CGROUP "/cgroup.procs", O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "\t  [child] open cgroup.procs: %s\n", strerror(errno));
		_exit(1);
	}
	snprintf(buf, sizeof(buf), "%d", getpid());
	write(fd, buf, strlen(buf));
	close(fd);
	usleep(100000);  /* 等待 cgroup 成员身份生效 */
	fprintf(stderr, "\t  [child] moved into cgroup (pid=%d)\n\n", getpid());

	/* 测试 1：open /dev/zero + read → 应成功（白名单允许 read） */
	fprintf(stderr, "\t  [child] test 1: open /dev/zero for read...\n");
	fd = open("/dev/zero", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "\t  [child] FAIL: open /dev/zero: %s\n", strerror(errno));
		_exit(1);
	}
	ret = read(fd, buf, 4);
	close(fd);
	if (ret != 4) {
		fprintf(stderr, "\t  [child] FAIL: read /dev/zero returned %d\n", ret);
		_exit(1);
	}
	fprintf(stderr, "\t  [child] PASS: /dev/zero read OK (got 4 bytes)\n\n");

	/* 测试 2：open /dev/mem + read → 应被拒绝（不在白名单） */
	fprintf(stderr, "\t  [child] test 2: open /dev/mem for read...\n");
	fd = open("/dev/mem", O_RDONLY);
	if (fd >= 0) {
		close(fd);
		fprintf(stderr, "\t  [child] FAIL: /dev/mem should be denied but open succeeded\n");
		_exit(1);
	}
	if (errno == EACCES || errno == EPERM) {
		fprintf(stderr, "\t  [child] PASS: /dev/mem denied (%s)\n\n", strerror(errno));
	} else {
		fprintf(stderr, "\t  [child] UNEXPECTED: /dev/mem errno=%d (%s)\n\n",
			errno, strerror(errno));
	}

	/* 测试 3：mknod 创建不在白名单中的设备节点 → 应被拒绝
	 * 使用 (1, 99) — 不在白名单中 */
	fprintf(stderr, "\t  [child] test 3: mknod testdev c 1 99...\n");
	ret = mknod("/tmp/cg-dev-testdev", S_IFCHR | 0600, makedev(1, 99));
	if (ret == 0) {
		unlink("/tmp/cg-dev-testdev");
		fprintf(stderr, "\t  [child] FAIL: mknod should be denied but succeeded\n");
		_exit(1);
	}
		if (errno == EACCES || errno == EPERM) {
			fprintf(stderr, "\t  [child] PASS: mknod denied (%s)\n\n", strerror(errno));
	} else {
		fprintf(stderr, "\t  [child] UNEXPECTED: mknod errno=%d (%s)\n\n",
			errno, strerror(errno));
	}

	fprintf(stderr, "\t  [child] All tests passed.\n");
	_exit(0);
}

int main(int argc, char **argv)
{
	struct cgroup_device_bpf *skel;
	struct bpf_link *link = NULL;
	struct ring_buffer *ringbuf = NULL;
	int err = 0, cg_fd = -1, allow_fd;
	pid_t child;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, SIG_IGN);  /* 父进程忽略 SIGINT，等子进程完成 */
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
	skel = cgroup_device_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* 3. 配置设备白名单 */
	allow_fd = bpf_map__fd(skel->maps.allowlist);
	for (int i = 0; i < NUM_ALLOW; i++) {
		struct dev_key key = { .major = allowlist[i].major, .minor = allowlist[i].minor };
		struct dev_val val = { .allow_mask = allowlist[i].allow_mask };
		if (bpf_map_update_elem(allow_fd, &key, &val, BPF_ANY) < 0) {
			fprintf(stderr, "map update %s: %s\n", allowlist[i].name, strerror(errno));
			err = 1;
			goto cleanup;
		}
	}

	/* 4. attach 到 cgroup */
	link = bpf_program__attach_cgroup(skel->progs.cg_dev_filter, cg_fd);
	if (!link) {
		fprintf(stderr, "attach_cgroup failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 5. 设置 ringbuf */
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ringbuf) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	printf("BPF cgroup/dev device allowlist attached to %s\n", DEMO_CGROUP);
	printf("  Allowlist:\n");
	for (int i = 0; i < NUM_ALLOW; i++)
		printf("    char %u:%u  (%-14s) → %s\n",
		       allowlist[i].major, allowlist[i].minor,
		       allowlist[i].name, access_str(allowlist[i].allow_mask));
	printf("\nChild (in cgroup) testing device access:\n");

	/* 6. fork 子进程进入 cgroup 测试 */
	child = fork();
	if (child == 0) {
		run_in_cgroup();
		_exit(0);
	} else if (child < 0) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* 父进程：消费 ringbuf 事件，等待子进程完成 */
	int status;
	while (waitpid(child, &status, WNOHANG) == 0) {
		ring_buffer__poll(ringbuf, 100);
	}

	printf("\nEvents from BPF (above) match the test results.\n");

cleanup:
	ring_buffer__free(ringbuf);
	if (link)
		bpf_link__destroy(link);
	if (skel)
		cgroup_device_bpf__destroy(skel);
	if (cg_fd >= 0)
		close(cg_fd);
	rmdir(DEMO_CGROUP);
	return err < 0 ? -err : 0;
}
