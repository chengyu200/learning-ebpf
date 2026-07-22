// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 51-cgroup-sysctl: 内核态 BPF 程序。
 *
 * 挂载类型：BPF_PROG_TYPE_CGROUP_SYSCTL（cgroup/sysctl）
 * 挂载点：/sys/fs/cgroup（根 cgroup，监控所有进程）
 *
 * 功能：当任何进程向 /proc/sys/net/ 下的 sysctl 写入新值时，
 *   1. 获取 sysctl 路径、旧值、新值
 *   2. 如果旧值 != 新值，通过 ringbuf 发送事件到用户态
 *   3. 始终返回 1（放行写入，仅监控不阻止）
 *
 * 参考：systemd 的 sysctl-monitor.bpf.c（commit 6d9ef22）
 *
 * 教学概念：
 * - BPF_PROG_TYPE_CGROUP_SYSCTL：拦截 cgroup 内进程的 sysctl 读写
 * - bpf_sysctl_get_name：获取 sysctl 路径（如 "net/ipv4/ip_forward"）
 * - bpf_sysctl_get_current_value：获取 sysctl 当前值
 * - bpf_sysctl_get_new_value：获取正在写入的新值
 * - bpf_strncmp：内核字符串比较 helper
 * - 返回 1 = 放行，返回 0 = 阻止
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "sysctl-monitor.h"

char LICENSE[] SEC("license") = "GPL";

/* ringbuf map：内核→用户态事件通道 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* 比较两个字符串是否相等（定长比较，遇 \0 提前结束） */
static __always_inline bool str_eq(const char *a, const char *b, int max_len)
{
	for (int i = 0; i < max_len; i++) {
		if (a[i] != b[i])
			return false;
		if (a[i] == '\0')
			return true;
	}
	return true;
}

/*
 * cgroup/sysctl 程序：每次 /proc/sys 读写都会触发。
 *
 * @ctx  bpf_sysctl 上下文
 *       ctx->write: 1=写操作, 0=读操作
 *       ctx->file_pos: 文件偏移
 * @return 1=允许操作, 0=拒绝操作
 */
SEC("cgroup/sysctl")
int sysctl_monitor(struct bpf_sysctl *ctx)
{
	struct sysctl_write_event *e;

	/* 只监控写操作，读操作直接放行 */
	if (!ctx->write)
		return 1;

	/* 在 ringbuf 中预留事件空间 */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 1;

	/* 初始化事件字段 */
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->path[0] = '\0';
	e->old_value[0] = '\0';
	e->new_value[0] = '\0';

	/* 获取 sysctl 路径（如 "net/ipv4/ip_forward"，不含 /proc/sys/ 前缀） */
	int ret = bpf_sysctl_get_name(ctx, e->path, sizeof(e->path), 0);
	if (ret < 0) {
		e->old_value[0] = '?';  /* 标记错误 */
		bpf_ringbuf_submit(e, 0);
		return 1;
	}

	/* 只监控 net/ 前缀的 sysctl */
	if (bpf_strncmp(e->path, 4, "net/") != 0) {
		bpf_ringbuf_discard(e, 0);
		return 1;
	}

	/* 获取当前值（写入前） */
	ret = bpf_sysctl_get_current_value(ctx, e->old_value, sizeof(e->old_value));
	if (ret < 0) {
		bpf_ringbuf_submit(e, 0);
		return 1;
	}

	/* 获取新值（正在写入的） */
	ret = bpf_sysctl_get_new_value(ctx, e->new_value, sizeof(e->new_value));
	if (ret < 0) {
		bpf_ringbuf_submit(e, 0);
		return 1;
	}

	/* 如果旧值和新值相同，不发送事件（去重） */
	if (str_eq(e->old_value, e->new_value, sizeof(e->old_value))) {
		bpf_ringbuf_discard(e, 0);
		return 1;
	}

	/* 值不同，提交事件到 ringbuf */
	bpf_ringbuf_submit(e, 0);
	return 1;
}
