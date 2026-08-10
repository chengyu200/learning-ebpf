// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 76-cgroup-device: 内核态 BPF 程序 — 设备白名单防火墙。
 *
 * SEC("cgroup/dev") 挂载到 cgroup，控制 cgroup 内进程对设备的访问。
 * 程序类型：BPF_PROG_TYPE_CGROUP_DEVICE
 * 挂载类型：BPF_CGROUP_DEVICE
 *
 * 上下文：struct bpf_cgroup_dev_ctx {
 *   __u32 access_type;  // 编码：(BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*
 *   __u32 major;
 *   __u32 minor;
 * }
 *
 * 返回值：1 = 允许访问，0 = 拒绝访问
 *
 * 策略：hash map 白名单
 *   - 用户态将允许的设备 (major, minor) → 允许的 access mask 写入 map
 *   - BPF 程序查找 map，检查请求的 access 是否被允许
 *   - 不在白名单中 → 拒绝
 *
 * 与 73-lsm-cgroup 的返回值对比：
 *   lsm_cgroup: 0=allow, 1=deny
 *   cgroup/dev: 1=allow, 0=deny  ← 相反！
 *
 * 教学概念：
 * - SEC("cgroup/dev") + bpf_program__attach_cgroup()
 * - bpf_cgroup_dev_ctx：access_type 编码 + major + minor
 * - BPF_DEVCG_ACC_MKNOD/READ/WRITE：三种设备访问操作
 * - BPF_DEVCG_DEV_BLOCK/CHAR：块设备/字符设备
 * - hash map 白名单：动态配置允许的设备列表
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "cgroup-device.h"

char LICENSE[] SEC("license") = "GPL";

/* 设备白名单 hash map：key=(major,minor) → value=allow_mask */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct dev_key);
	__type(value, struct dev_val);
} allowlist SEC(".maps");

/* ringbuf：设备访问事件通道 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("cgroup/dev")
int cg_dev_filter(struct bpf_cgroup_dev_ctx *ctx)
{
	struct dev_key key = {};
	struct dev_val *val;
	struct event *e;
	__u32 access_type = ctx->access_type;
	__u32 acc;	/* 请求的访问操作 */
	__u32 dev;	/* 设备类型 */
	int allowed = 0;

	/* access_type 编码：高 16 位 = 访问操作，低 16 位 = 设备类型 */
	acc = access_type >> 16;
	dev = access_type & 0xFFFF;

	/* 查找白名单 */
	key.major = ctx->major;
	key.minor = ctx->minor;
	val = bpf_map_lookup_elem(&allowlist, &key);

	if (val) {
		/* 在白名单中：检查请求的 access 是否被允许 */
		if (val->allow_mask & acc)
			allowed = 1;
	}
	/* 不在白名单中 → allowed = 0（拒绝） */

	/* 发送事件到 ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->dev_type = (__u8)dev;
		e->allowed  = (__u8)allowed;
		e->major    = ctx->major;
		e->minor    = ctx->minor;
		e->access   = acc;
		e->pid      = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}

	return allowed;
}
