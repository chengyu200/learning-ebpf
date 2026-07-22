// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 51-cgroup-sysctl: 用户态加载器。
 *
 * 加载 BPF 程序，挂载到根 cgroup（/sys/fs/cgroup），
 * 轮询 ringbuf 接收 sysctl 写入事件并打印。
 *
 * 用法：
 *   sudo ./sysctl-monitor
 *   # 另开终端：echo 1 > /proc/sys/net/ipv4/ip_forward
 *
 * 教学概念：
 * - bpf_program__attach_cgroup：将 BPF 程序挂到 cgroup
 * - ring_buffer__poll：从 ringbuf 读取内核事件
 * - BPF_PROG_TYPE_CGROUP_SYSCTL 程序的生命周期管理
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "sysctl-monitor.h"
#include "sysctl-monitor.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/*
 * ringbuf 事件回调：格式化打印 sysctl 写入事件。
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct sysctl_write_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-7d %-16s %-35s %s → %s\n",
	       ts, e->pid, e->comm, e->path,
	       e->old_value[0] ? e->old_value : "(empty)",
	       e->new_value[0] ? e->new_value : "(empty)");
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct sysctl_monitor_bpf *skel;
	struct bpf_link *link = NULL;
	int cgroup_fd, err = 0;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	setvbuf(stdout, NULL, _IONBF, 0);

	/* 加载 BPF 骨架 */
	skel = sysctl_monitor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* 打开根 cgroup（监控所有进程的 sysctl 写入） */
	cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
	if (cgroup_fd < 0) {
		fprintf(stderr, "Failed to open /sys/fs/cgroup: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 将 BPF 程序挂载到 cgroup */
	link = bpf_program__attach_cgroup(skel->progs.sysctl_monitor, cgroup_fd);
	close(cgroup_fd);
	if (!link) {
		fprintf(stderr, "Failed to attach cgroup program: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 创建 ringbuf 并注册回调 */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	printf("Monitoring sysctl writes under /proc/sys/net/... Ctrl-C\n");
	printf("%-8s %-7s %-16s %-35s %s\n",
	       "TIME", "PID", "COMM", "PATH", "OLD → NEW");

	/* 主循环：轮询 ringbuf */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	if (link)
		bpf_link__destroy(link);
	sysctl_monitor_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
