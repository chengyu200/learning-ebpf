# eBPF Helper 函数总结

> 来源：`libbpf/src/bpf_helper_defs.h`（211 个 helper）+ [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) man page
>
> eBPF 程序不能直接调用任意内核函数，只能调用内核白名单中的 helper。每个 helper 有一个 ID（即 `(void *) N` 中的 N），最多 5 个参数，调用无额外开销（直接编译为内联调用）。

---

## 目录

1. [Map 操作](#1-map-操作)
2. [Tracing / 调试](#2-tracing-调试)
3. [时间](#3-时间)
4. [进程 / 任务信息](#4-进程-任务信息)
5. [网络 — 包操作 (SKB/XDP)](#5-网络-包操作-skbxdp)
6. [网络 — 重定向 / 路由](#6-网络-重定向-路由)
7. [网络 — 隧道 / LWT](#7-网络-隧道-lwt)
8. [网络 — Socket / sk_msg](#8-网络-socket-sk_msg)
9. [网络 — VLAN](#9-网络-vlan)
10. [网络 — XDP 专用](#10-网络-xdp-专用)
11. [网络 — SKB 杂项](#11-网络-skb-杂项)
12. [Cgroup](#12-cgroup)
13. [Perf / Ring Buffer](#13-perf-ring-buffer)
14. [系统 / 内核信息](#14-系统-内核信息)
15. [Tail Call / 程序链接](#15-tail-call-程序链接)
16. [Sysctl](#16-sysctl)
17. [信号](#17-信号)
18. [定时器](#18-定时器)
19. [锁 / 同步](#19-锁-同步)
20. [BPF 核心 / 迭代器 / 格式化](#20-bpf-核心-迭代器-格式化)
21. [动态指针 (Dynptr)](#21-动态指针-dynptr)
22. [本地存储](#22-本地存储)
23. [其他](#23-其他)

- [快速索引表](#快速索引表)
- [按程序类型速查](#附录按程序类型的-helper-可用性速查)

---

## 快速索引表

| ID | Helper 名称 | 类别 |
|---|---|---|
| 1 | `bpf_map_lookup_elem` | Map 操作 |
| 2 | `bpf_map_update_elem` | Map 操作 |
| 3 | `bpf_map_delete_elem` | Map 操作 |
| 4 | `bpf_probe_read` | Tracing / 调试 |
| 5 | `bpf_ktime_get_ns` | 时间 |
| 6 | `bpf_trace_printk` | Tracing / 调试 |
| 7 | `bpf_get_prandom_u32` | 系统 / 内核信息 |
| 8 | `bpf_fastcall` | 系统 / 内核信息 |
| 9 | `bpf_skb_store_bytes` | 网络 |
| 10 | `bpf_l3_csum_replace` | 网络 |
| 11 | `bpf_l4_csum_replace` | 网络 |
| 12 | `bpf_tail_call` | Tail Call / 程序链接 |
| 13 | `bpf_clone_redirect` | 网络 |
| 14 | `bpf_get_current_pid_tgid` | 进程 / 任务信息 |
| 15 | `bpf_get_current_uid_gid` | 进程 / 任务信息 |
| 16 | `bpf_get_current_comm` | 进程 / 任务信息 |
| 17 | `bpf_get_cgroup_classid` | 网络 |
| 18 | `bpf_skb_vlan_push` | 网络 |
| 19 | `bpf_skb_vlan_pop` | 网络 |
| 20 | `bpf_skb_get_tunnel_key` | 网络 |
| 21 | `bpf_skb_set_tunnel_key` | 网络 |
| 22 | `bpf_perf_event_read` | Perf / Ring Buffer |
| 23 | `bpf_redirect` | 网络 |
| 24 | `bpf_get_route_realm` | 网络 |
| 25 | `bpf_perf_event_output` | Perf / Ring Buffer |
| 26 | `bpf_skb_load_bytes` | 网络 |
| 27 | `bpf_get_stackid` | Tracing / 调试 |
| 28 | `bpf_csum_diff` | 网络 |
| 29 | `bpf_skb_get_tunnel_opt` | 网络 |
| 30 | `bpf_skb_set_tunnel_opt` | 网络 |
| 31 | `bpf_skb_change_proto` | 网络 |
| 32 | `bpf_skb_change_type` | 网络 |
| 33 | `bpf_skb_under_cgroup` | 网络 |
| 34 | `bpf_get_hash_recalc` | 网络 |
| 35 | `bpf_get_current_task` | 进程 / 任务信息 |
| 36 | `bpf_probe_write_user` | 其他 |
| 37 | `bpf_current_task_under_cgroup` | Cgroup |
| 38 | `bpf_skb_change_tail` | 网络 |
| 39 | `bpf_skb_pull_data` | 网络 |
| 40 | `bpf_csum_update` | 网络 |
| 41 | `bpf_set_hash_invalid` | 网络 |
| 42 | `bpf_get_numa_node_id` | 系统 / 内核信息 |
| 43 | `bpf_skb_change_head` | 网络 |
| 44 | `bpf_xdp_adjust_head` | 网络 |
| 45 | `bpf_probe_read_str` | Tracing / 调试 |
| 46 | `bpf_get_socket_cookie` | 网络 |
| 47 | `bpf_get_socket_uid` | 网络 |
| 48 | `bpf_set_hash` | 网络 |
| 49 | `bpf_setsockopt` | 网络 |
| 50 | `bpf_skb_adjust_room` | 网络 |
| 51 | `bpf_redirect_map` | 网络 |
| 52 | `bpf_sk_redirect_map` | 网络 |
| 53 | `bpf_sock_map_update` | 网络 |
| 54 | `bpf_xdp_adjust_meta` | 网络 |
| 55 | `bpf_perf_event_read_value` | Perf / Ring Buffer |
| 56 | `bpf_perf_prog_read_value` | Perf / Ring Buffer |
| 57 | `bpf_getsockopt` | 网络 |
| 58 | `bpf_override_return` | 网络 |
| 59 | `bpf_sock_ops_cb_flags_set` | 网络 |
| 60 | `bpf_msg_redirect_map` | 网络 |
| 61 | `bpf_msg_apply_bytes` | 网络 |
| 62 | `bpf_msg_cork_bytes` | 网络 |
| 63 | `bpf_msg_pull_data` | 网络 |
| 64 | `bpf_bind` | 网络 |
| 65 | `bpf_xdp_adjust_tail` | 网络 |
| 66 | `bpf_skb_get_xfrm_state` | 网络 |
| 67 | `bpf_get_stack` | Tracing / 调试 |
| 68 | `bpf_skb_load_bytes_relative` | 网络 |
| 69 | `bpf_fib_lookup` | 网络 |
| 70 | `bpf_sock_hash_update` | 网络 |
| 71 | `bpf_msg_redirect_hash` | 网络 |
| 72 | `bpf_sk_redirect_hash` | 网络 |
| 73 | `bpf_lwt_push_encap` | 网络 |
| 74 | `bpf_lwt_seg6_store_bytes` | 网络 |
| 75 | `bpf_lwt_seg6_adjust_srh` | 网络 |
| 76 | `bpf_lwt_seg6_action` | 网络 |
| 77 | `bpf_rc_repeat` | 其他 |
| 78 | `bpf_rc_keydown` | 其他 |
| 79 | `bpf_skb_cgroup_id` | 网络 |
| 80 | `bpf_get_current_cgroup_id` | Cgroup |
| 81 | `bpf_get_local_storage` | 本地存储 |
| 82 | `bpf_sk_select_reuseport` | 网络 |
| 83 | `bpf_skb_ancestor_cgroup_id` | 网络 |
| 84 | `bpf_sock` | 网络 |
| 85 | `bpf_sock` | 网络 |
| 86 | `bpf_sk_release` | 网络 |
| 87 | `bpf_map_push_elem` | Map 操作 |
| 88 | `bpf_map_pop_elem` | Map 操作 |
| 89 | `bpf_map_peek_elem` | Map 操作 |
| 90 | `bpf_msg_push_data` | ? |
| 91 | `bpf_msg_pop_data` | ? |
| 92 | `bpf_rc_pointer_rel` | 其他 |
| 93 | `bpf_spin_lock` | 锁 / 同步 |
| 94 | `bpf_spin_unlock` | 锁 / 同步 |
| 95 | `bpf_sock` | 网络 |
| 96 | `bpf_tcp_sock` | 网络 |
| 97 | `bpf_skb_ecn_set_ce` | 网络 |
| 98 | `bpf_sock` | 网络 |
| 99 | `bpf_sock` | 网络 |
| 100 | `bpf_tcp_check_syncookie` | 网络 |
| 101 | `bpf_sysctl_get_name` | Sysctl |
| 102 | `bpf_sysctl_get_current_value` | Sysctl |
| 103 | `bpf_sysctl_get_new_value` | Sysctl |
| 104 | `bpf_sysctl_set_new_value` | Sysctl |
| 105 | `bpf_strtol` | Sysctl |
| 106 | `bpf_strtoul` | Sysctl |
| 107 | `bpf_sk_storage_get` | 本地存储 |
| 108 | `bpf_sk_storage_delete` | 本地存储 |
| 109 | `bpf_send_signal` | 信号 |
| 110 | `bpf_tcp_gen_syncookie` | Perf / Ring Buffer |
| 111 | `bpf_skb_output` | 网络 |
| 112 | `bpf_probe_read_user` | Tracing / 调试 |
| 113 | `bpf_probe_read_kernel` | Tracing / 调试 |
| 114 | `bpf_probe_read_user_str` | Tracing / 调试 |
| 115 | `bpf_probe_read_kernel_str` | Tracing / 调试 |
| 116 | `bpf_tcp_send_ack` | 网络 |
| 117 | `bpf_send_signal_thread` | 信号 |
| 118 | `bpf_jiffies64` | 时间 |
| 119 | `bpf_read_branch_records` | Tracing / 调试 |
| 120 | `bpf_get_ns_current_pid_tgid` | 进程 / 任务信息 |
| 121 | `bpf_xdp_output` | 网络 |
| 122 | `bpf_get_netns_cookie` | Cgroup |
| 123 | `bpf_get_current_ancestor_cgroup_id` | Cgroup |
| 124 | `bpf_sk_assign` | 网络 |
| 125 | `bpf_ktime_get_boot_ns` | 时间 |
| 126 | `bpf_seq_printf` | BPF 核心 / 迭代器 / 格式化 |
| 127 | `bpf_seq_write` | BPF 核心 / 迭代器 / 格式化 |
| 128 | `bpf_sk_cgroup_id` | 网络 |
| 129 | `bpf_sk_ancestor_cgroup_id` | 网络 |
| 130 | `bpf_ringbuf_output` | Perf / Ring Buffer |
| 131 | `bpf_ringbuf_reserve` | Perf / Ring Buffer |
| 132 | `bpf_ringbuf_submit` | Perf / Ring Buffer |
| 133 | `bpf_ringbuf_discard` | Perf / Ring Buffer |
| 134 | `bpf_ringbuf_query` | Perf / Ring Buffer |
| 135 | `bpf_csum_level` | 网络 |
| 136 | `bpf_skc_to_tcp6_sock` | 网络 |
| 137 | `bpf_skc_to_tcp_sock` | 网络 |
| 138 | `bpf_skc_to_tcp_timewait_sock` | 网络 |
| 139 | `bpf_skc_to_tcp_request_sock` | 网络 |
| 140 | `bpf_skc_to_udp6_sock` | 网络 |
| 141 | `bpf_get_task_stack` | Tracing / 调试 |
| 142 | `bpf_load_hdr_opt` | 网络 |
| 143 | `bpf_store_hdr_opt` | 网络 |
| 144 | `bpf_reserve_hdr_opt` | 网络 |
| 145 | `bpf_inode_storage_get` | 本地存储 |
| 146 | `bpf_inode_storage_delete` | 本地存储 |
| 147 | `bpf_d_path` | Tracing / 调试 |
| 148 | `bpf_copy_from_user` | BPF 核心 / 迭代器 / 格式化 |
| 149 | `bpf_snprintf_btf` | Tracing / 调试 |
| 150 | `bpf_seq_printf_btf` | BPF 核心 / 迭代器 / 格式化 |
| 151 | `bpf_skb_cgroup_classid` | 网络 |
| 152 | `bpf_redirect_neigh` | 网络 |
| 153 | `bpf_per_cpu_ptr` | ? |
| 154 | `bpf_this_cpu_ptr` | ? |
| 155 | `bpf_redirect_peer` | 网络 |
| 156 | `bpf_task_storage_get` | 本地存储 |
| 157 | `bpf_task_storage_delete` | 本地存储 |
| 158 | `bpf_get_current_task_btf` | 进程 / 任务信息 |
| 159 | `bpf_bprm_opts_set` | 其他 |
| 160 | `bpf_ktime_get_coarse_ns` | 时间 |
| 161 | `bpf_ima_inode_hash` | 其他 |
| 162 | `bpf_sock_from_file` | 其他 |
| 163 | `bpf_check_mtu` | 网络 |
| 164 | `bpf_for_each_map_elem` | Map 操作 |
| 165 | `bpf_snprintf` | Tracing / 调试 |
| 166 | `bpf_sys_bpf` | BPF 核心 / 迭代器 / 格式化 |
| 167 | `bpf_btf_find_by_name_kind` | BPF 核心 / 迭代器 / 格式化 |
| 168 | `bpf_sys_close` | BPF 核心 / 迭代器 / 格式化 |
| 169 | `bpf_timer_init` | 定时器 |
| 170 | `bpf_timer_set_callback` | 定时器 |
| 171 | `bpf_timer_start` | 定时器 |
| 172 | `bpf_timer_cancel` | 定时器 |
| 173 | `bpf_get_func_ip` | Tracing / 调试 |
| 174 | `bpf_get_attach_cookie` | Tail Call / 程序链接 |
| 175 | `bpf_task_pt_regs` | Tracing / 调试 |
| 176 | `bpf_get_branch_snapshot` | Tracing / 调试 |
| 177 | `bpf_trace_vprintk` | Tracing / 调试 |
| 178 | `bpf_skc_to_unix_sock` | 网络 |
| 179 | `bpf_kallsyms_lookup_name` | Tracing / 调试 |
| 180 | `bpf_find_vma` | Tracing / 调试 |
| 181 | `bpf_loop` | BPF 核心 / 迭代器 / 格式化 |
| 182 | `bpf_strncmp` | Tracing / 调试 |
| 183 | `bpf_get_func_arg` | Tracing / 调试 |
| 184 | `bpf_get_func_ret` | Tracing / 调试 |
| 185 | `bpf_get_func_arg_cnt` | Tracing / 调试 |
| 186 | `bpf_get_retval` | Tracing / 调试 |
| 187 | `bpf_set_retval` | Tracing / 调试 |
| 188 | `bpf_xdp_get_buff_len` | 网络 |
| 189 | `bpf_xdp_load_bytes` | 网络 |
| 190 | `bpf_xdp_store_bytes` | 网络 |
| 191 | `bpf_copy_from_user_task` | 其他 |
| 192 | `bpf_skb_set_tstamp` | 网络 |
| 193 | `bpf_ima_file_hash` | 网络 |
| 194 | `bpf_kptr_xchg` | Map 操作 |
| 195 | `bpf_map_lookup_percpu_elem` | Map 操作 |
| 196 | `bpf_skc_to_mptcp_sock` | 网络 |
| 197 | `bpf_dynptr_from_mem` | 动态指针 |
| 198 | `bpf_ringbuf_reserve_dynptr` | 动态指针 |
| 199 | `bpf_ringbuf_submit_dynptr` | 动态指针 |
| 200 | `bpf_ringbuf_discard_dynptr` | 动态指针 |
| 201 | `bpf_dynptr_read` | 动态指针 |
| 202 | `bpf_dynptr_write` | 动态指针 |
| 203 | `bpf_dynptr_data` | 动态指针 |
| 204 | `bpf_tcp_raw_gen_syncookie_ipv4` | 网络 |
| 205 | `bpf_tcp_raw_gen_syncookie_ipv6` | 网络 |
| 206 | `bpf_tcp_raw_check_syncookie_ipv4` | 网络 |
| 207 | `bpf_tcp_raw_check_syncookie_ipv6` | 网络 |
| 208 | `bpf_ktime_get_tai_ns` | 时间 |
| 209 | `bpf_user_ringbuf_drain` | Perf / Ring Buffer |
| 210 | `bpf_cgrp_storage_get` | 本地存储 |
| 211 | `bpf_cgrp_storage_delete` | 本地存储 |

---

## 1. Map 操作（9 个）

### #1 `bpf_map_lookup_elem`

```c
void * bpf_map_lookup_elem(void *map, const void *key);
```

**描述：** Perform a lookup in map for an entry associated to key.

**返回：** Map value associated to key, or NULL if no entry was found.

### #2 `bpf_map_update_elem`

```c
long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);
```

**描述：** Add or update the value of the entry associated to key in map with value. flags is one of: BPF_NOEXIST The entry for key must not exist in the map. BPF_EXIST The entry for key must already exist in the map. BPF_ANY No condition on the existence of...

**返回：** 0 on success, or a negative error in case of failure.

### #3 `bpf_map_delete_elem`

```c
long bpf_map_delete_elem(void *map, const void *key);
```

**描述：** Delete entry with key from map.

**返回：** 0 on success, or a negative error in case of failure.

### #87 `bpf_map_push_elem`

```c
long bpf_map_push_elem(void *map, const void *value, __u64 flags);
```

**描述：** Push an element value in map. flags is one of: BPF_EXIST If the queue/stack is full, the oldest element is removed to make room for this.

**返回：** 0 on success, or a negative error in case of failure.

### #88 `bpf_map_pop_elem`

```c
long bpf_map_pop_elem(void *map, void *value);
```

**描述：** Pop an element from map.

**返回：** 0 on success, or a negative error in case of failure.

### #89 `bpf_map_peek_elem`

```c
long bpf_map_peek_elem(void *map, void *value);
```

**描述：** Get an element from map without removing it.

**返回：** 0 on success, or a negative error in case of failure.

### #164 `bpf_for_each_map_elem`

```c
long bpf_for_each_map_elem(void *map, void *callback_fn, void *callback_ctx, __u64 flags);
```

**描述：** For each element in map, call callback_fn function with map, callback_ctx and other map-specific parameters. The callback_fn should be a static function and the callback_ctx should be a pointer to the stack. The flags is used to control certain as...

**返回：** The number of traversed map elements for success, -EINVAL for invalid flags.

### #194 `bpf_kptr_xchg`

```c
void * bpf_kptr_xchg(void *dst, void *ptr);
```

**描述：** Exchange kptr at pointer dst with ptr, and return the old value. dst can be map value or local kptr. ptr can be NULL, otherwise it must be a referenced pointer which will be released when this helper is called.

**返回：** The old value of kptr (which can be NULL). The returned pointer if not NULL, is a reference which must be released using its corresponding release function, or moved into a BPF map before program exit.

### #195 `bpf_map_lookup_percpu_elem`

```c
void * bpf_map_lookup_percpu_elem(void *map, const void *key, __u32 cpu);
```

**描述：** Perform a lookup in percpu map for an entry associated to key on cpu.

**返回：** Map value associated to key on cpu, or NULL if no entry was found or cpu is invalid.

---

## 2. Tracing / 调试（27 个）

### #4 `bpf_probe_read`

```c
long bpf_probe_read(void *dst, __u32 size, const void *unsafe_ptr);
```

**描述：** For tracing programs, safely attempt to read size bytes from kernel space address unsafe_ptr and store the data in dst. Generally, use bpf_probe_read_user\ () or bpf_probe_read_kernel\ () instead.

**返回：** 0 on success, or a negative error in case of failure.

### #6 `bpf_trace_printk`

```c
long bpf_trace_printk(const char *fmt, __u32 fmt_size, ...);
```

**描述：** This helper is a "printk()-like" facility for debugging. It prints a message defined by format fmt (of size fmt_size) to file \/sys/kernel/tracing/trace from TraceFS, if available. It can take up to three additional u64 arguments (as an eBPF helpe...

**返回：** The number of bytes written to the buffer, or a negative error in case of failure.

### #27 `bpf_get_stackid`

```c
long bpf_get_stackid(void *ctx, void *map, __u64 flags);
```

**描述：** Walk a user or a kernel stack and return its id. To achieve this, the helper needs ctx, which is a pointer to the context on which the tracing program is executed, and a pointer to a map of type BPF_MAP_TYPE_STACK_TRACE. The last argument, flags, ...

**返回：** The positive or null stack id on success, or a negative error in case of failure.

### #45 `bpf_probe_read_str`

```c
long bpf_probe_read_str(void *dst, __u32 size, const void *unsafe_ptr);
```

**描述：** Copy a NUL terminated string from an unsafe kernel address unsafe_ptr to dst. See bpf_probe_read_kernel_str\ () for more details. Generally, use bpf_probe_read_user_str\ () or bpf_probe_read_kernel_str\ () instead.

**返回：** On success, the strictly positive length of the string, including the trailing NUL character. On error, a negative value.

### #67 `bpf_get_stack`

```c
long bpf_get_stack(void *ctx, void *buf, __u32 size, __u64 flags);
```

**描述：** Return a user or a kernel stack in bpf program provided buffer. To achieve this, the helper needs ctx, which is a pointer to the context on which the tracing program is executed. To store the stacktrace, the bpf program provides buf with a nonnega...

**返回：** The non-negative copied buf length equal to or less than size on success, or a negative error in case of failure.

### #112 `bpf_probe_read_user`

```c
long bpf_probe_read_user(void *dst, __u32 size, const void *unsafe_ptr);
```

**描述：** Safely attempt to read size bytes from user space address unsafe_ptr and store the data in dst.

**返回：** 0 on success, or a negative error in case of failure.

### #113 `bpf_probe_read_kernel`

```c
long bpf_probe_read_kernel(void *dst, __u32 size, const void *unsafe_ptr);
```

**描述：** Safely attempt to read size bytes from kernel space address unsafe_ptr and store the data in dst.

**返回：** 0 on success, or a negative error in case of failure.

### #114 `bpf_probe_read_user_str`

```c
long bpf_probe_read_user_str(void *dst, __u32 size, const void *unsafe_ptr);
```

**描述：** Copy a NUL terminated string from an unsafe user address unsafe_ptr to dst. The size should include the terminating NUL byte. In case the string length is smaller than size, the target is not padded with further NUL bytes. If the string length is ...

**返回：** On success, the strictly positive length of the output string, including the trailing NUL character. On error, a negative value.

### #115 `bpf_probe_read_kernel_str`

```c
long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *unsafe_ptr);
```

**描述：** Copy a NUL terminated string from an unsafe kernel address unsafe_ptr to dst. Same semantics as with bpf_probe_read_user_str\ () apply.

**返回：** On success, the strictly positive length of the string, including the trailing NUL character. On error, a negative value.

### #119 `bpf_read_branch_records`

```c
long bpf_read_branch_records(struct bpf_perf_event_data *ctx, void *buf, __u32 size, __u64 flags);
```

**描述：** For an eBPF program attached to a perf event, retrieve the branch records (struct perf_branch_entry) associated to ctx and store it in the buffer pointed by buf up to size size bytes.

**返回：** On success, number of bytes written to buf. On error, a negative value. The flags can be set to BPF_F_GET_BRANCH_RECORDS_SIZE to instead return the number of bytes required to store all the branch entries. If this flag is set, buf may be NULL. -EI...

### #141 `bpf_get_task_stack`

```c
long bpf_get_task_stack(struct task_struct *task, void *buf, __u32 size, __u64 flags);
```

**描述：** Return a user or a kernel stack in bpf program provided buffer. Note: the user stack will only be populated if the task is the current task; all other tasks will return -EOPNOTSUPP. To achieve this, the helper needs task, which is a valid pointer ...

**返回：** The non-negative copied buf length equal to or less than size on success, or a negative error in case of failure.

### #147 `bpf_d_path`

```c
long bpf_d_path(const struct path *path, char *buf, __u32 sz);
```

**描述：** Return full path for given struct path object, which needs to be the kernel BTF path object. The path is returned in the provided buffer buf of size sz and is zero terminated.

**返回：** On success, the strictly positive length of the string, including the trailing NUL character. On error, a negative value.

### #149 `bpf_snprintf_btf`

```c
long bpf_snprintf_btf(char *str, __u32 str_size, struct btf_ptr *ptr, __u32 btf_ptr_size, __u64 flags);
```

**描述：** Use BTF to store a string representation of ptr->ptr in str, using ptr->type_id.  This value should specify the type that ptr->ptr points to. LLVM __builtin_btf_type_id(type, 1) can be used to look up vmlinux BTF type ids. Traversing the data stru...

**返回：** The number of bytes that were written (or would have been written if output had to be truncated due to string size), or a negative error in cases of failure.

### #150 `bpf_seq_printf_btf`

```c
long bpf_seq_printf_btf(struct seq_file *m, struct btf_ptr *ptr, __u32 ptr_size, __u64 flags);
```

**描述：** Use BTF to write to seq_write a string representation of ptr->ptr, using ptr->type_id as per bpf_snprintf_btf(). flags are identical to those used for bpf_snprintf_btf.

**返回：** 0 on success or a negative error in case of failure.

### #165 `bpf_snprintf`

```c
long bpf_snprintf(char *str, __u32 str_size, const char *fmt, __u64 *data, __u32 data_len);
```

**描述：** Outputs a string into the str buffer of size str_size based on a format string stored in a read-only map pointed by fmt. Each format specifier in fmt corresponds to one u64 element in the data array. For strings and pointers where pointees are acc...

**返回：** The strictly positive length of the formatted string, including the trailing zero character. If the return value is greater than str_size, str contains a truncated string, guaranteed to be zero-terminated except when str_size is 0. Or -EBUSY if th...

### #173 `bpf_get_func_ip`

```c
__u64 bpf_get_func_ip(void *ctx);
```

**描述：** Get address of the traced function (for tracing and kprobe programs). When called for kprobe program attached as uprobe it returns probe address for both entry and return uprobe.

**返回：** Address of the traced function for kprobe. 0 for kprobes placed within the function (not at the entry). Address of the probe for uprobe and return uprobe.

### #175 `bpf_task_pt_regs`

```c
long bpf_task_pt_regs(struct task_struct *task);
```

**描述：** Get the struct pt_regs associated with task.

**返回：** A pointer to struct pt_regs.

### #176 `bpf_get_branch_snapshot`

```c
long bpf_get_branch_snapshot(void *entries, __u32 size, __u64 flags);
```

**描述：** Get branch trace from hardware engines like Intel LBR. The hardware engine is stopped shortly after the helper is called. Therefore, the user need to filter branch entries based on the actual use case. To capture branch trace before the trigger po...

**返回：** On success, number of bytes written to buf. On error, a negative value. -EINVAL if flags is not zero. -ENOENT if architecture does not support branch records.

### #177 `bpf_trace_vprintk`

```c
long bpf_trace_vprintk(const char *fmt, __u32 fmt_size, const void *data, __u32 data_len);
```

**描述：** Behaves like bpf_trace_printk\ () helper, but takes an array of u64 to format and can handle more format args as a result. Arguments are to be used as in bpf_seq_printf\ () helper.

**返回：** The number of bytes written to the buffer, or a negative error in case of failure.

### #179 `bpf_kallsyms_lookup_name`

```c
long bpf_kallsyms_lookup_name(const char *name, int name_sz, int flags, __u64 *res);
```

**描述：** Get the address of a kernel symbol, returned in res. res is set to 0 if the symbol is not found.

**返回：** On success, zero. On error, a negative value. -EINVAL if flags is not zero. -EINVAL if string name is not the same size as name_sz. -ENOENT if symbol is not found. -EPERM if caller does not have permission to obtain kernel address.

### #180 `bpf_find_vma`

```c
long bpf_find_vma(struct task_struct *task, __u64 addr, void *callback_fn, void *callback_ctx, __u64 flags);
```

**描述：** Find vma of task that contains addr, call callback_fn function with task, vma, and callback_ctx. The callback_fn should be a static function and the callback_ctx should be a pointer to the stack. The flags is used to control certain aspects of the...

**返回：** 0 on success. -ENOENT if task->mm is NULL, or no vma contains addr. -EBUSY if failed to try lock mmap_lock. -EINVAL for invalid flags.

### #182 `bpf_strncmp`

```c
long bpf_strncmp(const char *s1, __u32 s1_sz, const char *s2);
```

**描述：** Do strncmp() between s1 and s2. s1 doesn't need to be null-terminated and s1_sz is the maximum storage size of s1. s2 must be a read-only string.

**返回：** An integer less than, equal to, or greater than zero if the first s1_sz bytes of s1 is found to be less than, to match, or be greater than s2.

### #183 `bpf_get_func_arg`

```c
long bpf_get_func_arg(void *ctx, __u32 n, __u64 *value);
```

**描述：** Get n-th argument register (zero based) of the traced function (for tracing programs) returned in value.

**返回：** 0 on success. -EINVAL if n >= argument register count of traced function.

### #184 `bpf_get_func_ret`

```c
long bpf_get_func_ret(void *ctx, __u64 *value);
```

**描述：** Get return value of the traced function (for tracing programs) in value.

**返回：** 0 on success. -EOPNOTSUPP for tracing programs other than BPF_TRACE_FEXIT or BPF_MODIFY_RETURN.

### #185 `bpf_get_func_arg_cnt`

```c
long bpf_get_func_arg_cnt(void *ctx);
```

**描述：** Get number of registers of the traced function (for tracing programs) where function arguments are stored in these registers.

**返回：** The number of argument registers of the traced function.

### #186 `bpf_get_retval`

```c
int bpf_get_retval(void);
```

**描述：** Get the BPF program's return value that will be returned to the upper layers. This helper is currently supported by cgroup programs and only by the hooks where BPF program's return value is returned to the userspace via errno.

**返回：** The BPF program's return value.

### #187 `bpf_set_retval`

```c
int bpf_set_retval(int retval);
```

**描述：** Set the BPF program's return value that will be returned to the upper layers. This helper is currently supported by cgroup programs and only by the hooks where BPF program's return value is returned to the userspace via errno. Note that there is t...

**返回：** 0 on success, or a negative error in case of failure.

---

## 3. 时间（5 个）

### #5 `bpf_ktime_get_ns`

```c
__u64 bpf_ktime_get_ns(void);
```

**描述：** Return the time elapsed since system boot, in nanoseconds. Does not include time the system was suspended. See: clock_gettime\ (CLOCK_MONOTONIC)

**返回：** Current ktime.

### #118 `bpf_jiffies64`

```c
__u64 bpf_jiffies64(void);
```

**描述：** Obtain the 64bit jiffies

**返回：** The 64 bit jiffies

### #125 `bpf_ktime_get_boot_ns`

```c
__u64 bpf_ktime_get_boot_ns(void);
```

**描述：** Return the time elapsed since system boot, in nanoseconds. Does include the time the system was suspended. See: clock_gettime\ (CLOCK_BOOTTIME)

**返回：** Current ktime.

### #160 `bpf_ktime_get_coarse_ns`

```c
__u64 bpf_ktime_get_coarse_ns(void);
```

**描述：** Return a coarse-grained version of the time elapsed since system boot, in nanoseconds. Does not include time the system was suspended. See: clock_gettime\ (CLOCK_MONOTONIC_COARSE)

**返回：** Current ktime.

### #208 `bpf_ktime_get_tai_ns`

```c
__u64 bpf_ktime_get_tai_ns(void);
```

**描述：** A nonsettable system-wide clock derived from wall-clock time but ignoring leap seconds.  This clock does not experience discontinuities and backwards jumps caused by NTP inserting leap seconds as CLOCK_REALTIME does. See: clock_gettime\ (CLOCK_TAI)

**返回：** Current ktime.

---

## 4. 进程 / 任务信息（7 个）

### #14 `bpf_get_current_pid_tgid`

```c
__u64 bpf_get_current_pid_tgid(void);
```

**描述：** Get the current pid and tgid.

**返回：** A 64-bit integer containing the current tgid and pid, and created as such: current_task\ ->tgid << 32 \| current_task\ ->pid.

### #15 `bpf_get_current_uid_gid`

```c
__u64 bpf_get_current_uid_gid(void);
```

**描述：** Get the current uid and gid.

**返回：** A 64-bit integer containing the current GID and UID, and created as such: current_gid << 32 \| current_uid.

### #16 `bpf_get_current_comm`

```c
long bpf_get_current_comm(void *buf, __u32 size_of_buf);
```

**描述：** Copy the comm attribute of the current task into buf of size_of_buf. The comm attribute contains the name of the executable (excluding the path) for the current task. The size_of_buf must be strictly positive. On success, the helper makes sure tha...

**返回：** 0 on success, or a negative error in case of failure.

### #35 `bpf_get_current_task`

```c
__u64 bpf_get_current_task(void);
```

**描述：** Get the current task.

**返回：** A pointer to the current task struct.

### #120 `bpf_get_ns_current_pid_tgid`

```c
long bpf_get_ns_current_pid_tgid(__u64 dev, __u64 ino, struct bpf_pidns_info *nsdata, __u32 size);
```

**描述：** 

**返回：** namespace will be returned in nsdata. 0 on success, or one of the following in case of failure: -EINVAL if dev and inum supplied don't match dev_t and inode number with nsfs of current task, or if dev conversion to dev_t lost high bits. -ENOENT if...

### #123 `bpf_get_current_ancestor_cgroup_id`

```c
__u64 bpf_get_current_ancestor_cgroup_id(int ancestor_level);
```

**描述：** Return id of cgroup v2 that is ancestor of the cgroup associated with the current task at the ancestor_level. The root cgroup is at ancestor_level zero and each step down the hierarchy increments the level. If ancestor_level == level of cgroup ass...

**返回：** The id is returned or 0 in case the id could not be retrieved.

### #158 `bpf_get_current_task_btf`

```c
struct task_struct * bpf_get_current_task_btf(void);
```

**描述：** Return a BTF pointer to the "current" task. This pointer can also be used in helpers that accept an ARG_PTR_TO_BTF_ID of type task_struct.

**返回：** Pointer to the current task.

---

## 5. 网络 — 包操作 (SKB/XDP)（23 个）

### #9 `bpf_skb_store_bytes`

```c
long bpf_skb_store_bytes(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags);
```

**描述：** Store len bytes from address from into the packet associated to skb, at offset. The flags are a combination of the following values: BPF_F_RECOMPUTE_CSUM Automatically update skb\ ->csum after storing the bytes. BPF_F_INVALIDATE_HASH Set skb\ ->ha...

**返回：** 0 on success, or a negative error in case of failure.

### #10 `bpf_l3_csum_replace`

```c
long bpf_l3_csum_replace(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size);
```

**描述：** Recompute the layer 3 (e.g. IP) checksum for the packet associated to skb. Computation is incremental, so the helper must know the former value of the header field that was modified (from), the new value of this field (to), and the number of bytes...

**返回：** 0 on success, or a negative error in case of failure.

### #11 `bpf_l4_csum_replace`

```c
long bpf_l4_csum_replace(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags);
```

**描述：** Recompute the layer 4 (e.g. TCP, UDP or ICMP) checksum for the packet associated to skb. Computation is incremental, so the helper must know the former value of the header field that was modified (from), the new value of this field (to), and the n...

**返回：** 0 on success, or a negative error in case of failure.

### #26 `bpf_skb_load_bytes`

```c
long bpf_skb_load_bytes(const void *skb, __u32 offset, void *to, __u32 len);
```

**描述：** This helper was provided as an easy way to load data from a packet. It can be used to load len bytes from offset from the packet associated to skb, into the buffer pointed by to. Since Linux 4.7, usage of this helper has mostly been replaced by "d...

**返回：** 0 on success, or a negative error in case of failure.

### #28 `bpf_csum_diff`

```c
__s64 bpf_csum_diff(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed);
```

**描述：** Compute a checksum difference, from the raw buffer pointed by from, of length from_size (that must be a multiple of 4), towards the raw buffer pointed by to, of size to_size (same remark). An optional seed can be added to the value (this can be ca...

**返回：** The checksum result, or a negative error code in case of failure.

### #31 `bpf_skb_change_proto`

```c
long bpf_skb_change_proto(struct __sk_buff *skb, __be16 proto, __u64 flags);
```

**描述：** Change the protocol of the skb to proto. Currently supported are transition from IPv4 to IPv6, and from IPv6 to IPv4. The helper takes care of the groundwork for the transition, including resizing the socket buffer. The eBPF program is expected to...

**返回：** 0 on success, or a negative error in case of failure.

### #32 `bpf_skb_change_type`

```c
long bpf_skb_change_type(struct __sk_buff *skb, __u32 type);
```

**描述：** Change the packet type for the packet associated to skb. This comes down to setting skb\ ->pkt_type to type, except the eBPF program does not have a write access to skb\ ->pkt_type beside this helper. Using a helper here allows for graceful handli...

**返回：** 0 on success, or a negative error in case of failure.

### #38 `bpf_skb_change_tail`

```c
long bpf_skb_change_tail(struct __sk_buff *skb, __u32 len, __u64 flags);
```

**描述：** Resize (trim or grow) the packet associated to skb to the new len. The flags are reserved for future usage, and must be left at zero. The basic idea is that the helper performs the needed work to change the size of the packet, then the eBPF progra...

**返回：** 0 on success, or a negative error in case of failure.

### #39 `bpf_skb_pull_data`

```c
long bpf_skb_pull_data(struct __sk_buff *skb, __u32 len);
```

**描述：** Pull in non-linear data in case the skb is non-linear and not all of len are part of the linear section. Make len bytes from skb readable and writable. If a zero value is passed for len, then all bytes in the linear part of skb will be made readab...

**返回：** 0 on success, or a negative error in case of failure.

### #40 `bpf_csum_update`

```c
__s64 bpf_csum_update(struct __sk_buff *skb, __wsum csum);
```

**描述：** Add the checksum csum into skb\ ->csum in case the driver has supplied a checksum for the entire packet into that field. Return an error otherwise. This helper is intended to be used in combination with bpf_csum_diff\ (), in particular when the ch...

**返回：** The checksum on success, or a negative error code in case of failure.

### #41 `bpf_set_hash_invalid`

```c
void bpf_set_hash_invalid(struct __sk_buff *skb);
```

**描述：** Invalidate the current skb\ ->hash. It can be used after mangling on headers through direct packet access, in order to indicate that the hash is outdated and to trigger a recalculation the next time the kernel tries to access this hash or when the...

**返回：** void.

### #43 `bpf_skb_change_head`

```c
long bpf_skb_change_head(struct __sk_buff *skb, __u32 len, __u64 flags);
```

**描述：** Grows headroom of packet associated to skb and adjusts the offset of the MAC header accordingly, adding len bytes of space. It automatically extends and reallocates memory as required. This helper can be used on a layer 3 skb to push a MAC header ...

**返回：** 0 on success, or a negative error in case of failure.

### #48 `bpf_set_hash`

```c
long bpf_set_hash(struct __sk_buff *skb, __u32 hash);
```

**描述：** Set the full hash for skb (set the field skb\ ->hash) to value hash.

**返回：** 0

### #50 `bpf_skb_adjust_room`

```c
long bpf_skb_adjust_room(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags);
```

**描述：** Grow or shrink the room for data in the packet associated to skb by len_diff, and according to the selected mode. By default, the helper will reset any offloaded checksum indicator of the skb to CHECKSUM_NONE. This can be avoided by the following ...

**返回：** 0 on success, or a negative error in case of failure.

### #68 `bpf_skb_load_bytes_relative`

```c
long bpf_skb_load_bytes_relative(const void *skb, __u32 offset, void *to, __u32 len, __u32 start_header);
```

**描述：** This helper is similar to bpf_skb_load_bytes\ () in that it provides an easy way to load len bytes from offset from the packet associated to skb, into the buffer pointed by to. The difference to bpf_skb_load_bytes\ () is that a fifth argument star...

**返回：** 0 on success, or a negative error in case of failure.

### #97 `bpf_skb_ecn_set_ce`

```c
long bpf_skb_ecn_set_ce(struct __sk_buff *skb);
```

**描述：** Set ECN (Explicit Congestion Notification) field of IP header to CE (Congestion Encountered) if current value is ECT (ECN Capable Transport). Otherwise, do nothing. Works with IPv6 and IPv4.

**返回：** 1 if the CE flag is set (either by the current helper call or because it was already present), 0 if it is not set.

### #111 `bpf_skb_output`

```c
long bpf_skb_output(void *ctx, void *map, __u64 flags, void *data, __u64 size);
```

**描述：** Write raw data blob into a special BPF perf event held by map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY. This perf event must have the following attributes: PERF_SAMPLE_RAW as sample_type, PERF_TYPE_SOFTWARE as type, and PERF_COUNT_SW_BPF_OUTPUT as co...

**返回：** 0 on success, or a negative error in case of failure.

### #135 `bpf_csum_level`

```c
long bpf_csum_level(struct __sk_buff *skb, __u64 level);
```

**描述：** Change the skbs checksum level by one layer up or down, or reset it entirely to none in order to have the stack perform checksum validation. The level is applicable to the following protocols: TCP, UDP, GRE, SCTP, FCOE. For example, a decap of | E...

**返回：** 0 on success, or a negative error in case of failure. In the case of BPF_CSUM_LEVEL_QUERY, the current skb->csum_level is returned or the error code -EACCES in case the skb is not subject to CHECKSUM_UNNECESSARY.

### #163 `bpf_check_mtu`

```c
long bpf_check_mtu(void *ctx, __u32 ifindex, __u32 *mtu_len, __s32 len_diff, __u64 flags);
```

**描述：** Check packet size against exceeding MTU of net device (based on ifindex).  This helper will likely be used in combination with helpers that adjust/change the packet size. The argument len_diff can be used for querying with a planned size change. T...

**返回：**  0 on success, and populate MTU value in mtu_len pointer.  < 0 if any input argument is invalid (mtu_len not updated) MTU violations return positive values, but also populate MTU value in mtu_len pointer, as this can be needed for implementing PMT...

### #188 `bpf_xdp_get_buff_len`

```c
__u64 bpf_xdp_get_buff_len(struct xdp_md *xdp_md);
```

**描述：** Get the total size of a given xdp buff (linear and paged area)

**返回：** The total size of a given xdp buffer.

### #189 `bpf_xdp_load_bytes`

```c
long bpf_xdp_load_bytes(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len);
```

**描述：** This helper is provided as an easy way to load data from a xdp buffer. It can be used to load len bytes from offset from the frame associated to xdp_md, into the buffer pointed by buf.

**返回：** 0 on success, or a negative error in case of failure.

### #190 `bpf_xdp_store_bytes`

```c
long bpf_xdp_store_bytes(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len);
```

**描述：** Store len bytes from buffer buf into the frame associated to xdp_md, at offset.

**返回：** 0 on success, or a negative error in case of failure.

### #192 `bpf_skb_set_tstamp`

```c
long bpf_skb_set_tstamp(struct __sk_buff *skb, __u64 tstamp, __u32 tstamp_type);
```

**描述：** Change the __sk_buff->tstamp_type to tstamp_type and set tstamp to the __sk_buff->tstamp together. If there is no need to change the __sk_buff->tstamp_type, the tstamp value can be directly written to __sk_buff->tstamp instead. BPF_SKB_TSTAMP_DELI...

**返回：** 0 on success. -EINVAL for invalid input -EOPNOTSUPP for unsupported protocol

---

## 6. 网络 — 重定向 / 路由（7 个）

### #13 `bpf_clone_redirect`

```c
long bpf_clone_redirect(struct __sk_buff *skb, __u32 ifindex, __u64 flags);
```

**描述：** Clone and redirect the packet associated to skb to another net device of index ifindex. Both ingress and egress interfaces can be used for redirection. The BPF_F_INGRESS value in flags is used to make the distinction (ingress path is selected if t...

**返回：** 0 on success, or a negative error in case of failure. Positive error indicates a potential drop or congestion in the target device. The particular positive error codes are not defined.

### #23 `bpf_redirect`

```c
long bpf_redirect(__u32 ifindex, __u64 flags);
```

**描述：** Redirect the packet to another net device of index ifindex. This helper is somewhat similar to bpf_clone_redirect\ (), except that the packet is not cloned, which provides increased performance. Except for XDP, both ingress and egress interfaces c...

**返回：** For XDP, the helper returns XDP_REDIRECT on success or XDP_ABORTED on error. For other program types, the values are TC_ACT_REDIRECT on success or TC_ACT_SHOT on error.

### #51 `bpf_redirect_map`

```c
long bpf_redirect_map(void *map, __u64 key, __u64 flags);
```

**描述：** Redirect the packet to the endpoint referenced by map at index key. Depending on its type, this map can contain references to net devices (for forwarding packets through other ports), or to CPUs (for redirecting XDP frames to another CPU; but this...

**返回：** XDP_REDIRECT on success, or the value of the two lower bits of the flags argument on error.

### #52 `bpf_sk_redirect_map`

```c
long bpf_sk_redirect_map(struct __sk_buff *skb, void *map, __u32 key, __u64 flags);
```

**描述：** Redirect the packet to the socket referenced by map (of type BPF_MAP_TYPE_SOCKMAP) at index key. Both ingress and egress interfaces can be used for redirection. The BPF_F_INGRESS value in flags is used to make the distinction (ingress path is sele...

**返回：** SK_PASS on success, or SK_DROP on error.

### #69 `bpf_fib_lookup`

```c
long bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags);
```

**描述：** Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded, the neighbor tables are searched for the nexthop. If successful (ie., FIB lookup shows forwarding and nexthop is resolve...

**返回：**  < 0 if any input argument is invalid    0 on success (packet is forwarded, nexthop neighbor exists)  > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack If lookup fails with BPF_FIB_LKUP_R...

### #152 `bpf_redirect_neigh`

```c
long bpf_redirect_neigh(__u32 ifindex, struct bpf_redir_neigh *params, int plen, __u64 flags);
```

**描述：** Redirect the packet to another net device of index ifindex and fill in L2 addresses from neighboring subsystem. This helper is somewhat similar to bpf_redirect\ (), except that it populates L2 addresses as well, meaning, internally, the helper rel...

**返回：** The helper returns TC_ACT_REDIRECT on success or TC_ACT_SHOT on error.

### #155 `bpf_redirect_peer`

```c
long bpf_redirect_peer(__u32 ifindex, __u64 flags);
```

**描述：** Redirect the packet to another net device of index ifindex. This helper is somewhat similar to bpf_redirect\ (), except that the redirection happens to the ifindex' peer device. If flags is 0, the netns switch takes place from ingress to ingress w...

**返回：** The helper returns TC_ACT_REDIRECT on success or TC_ACT_SHOT on error.

---

## 7. 网络 — 隧道 / LWT（8 个）

### #20 `bpf_skb_get_tunnel_key`

```c
long bpf_skb_get_tunnel_key(struct __sk_buff *skb, struct bpf_tunnel_key *key, __u32 size, __u64 flags);
```

**描述：** Get tunnel metadata. This helper takes a pointer key to an empty struct bpf_tunnel_key of size, that will be filled with tunnel metadata for the packet associated to skb. The flags can be set to BPF_F_TUNINFO_IPV6, which indicates that the tunnel ...

**返回：** 0 on success, or a negative error in case of failure.

### #21 `bpf_skb_set_tunnel_key`

```c
long bpf_skb_set_tunnel_key(struct __sk_buff *skb, struct bpf_tunnel_key *key, __u32 size, __u64 flags);
```

**描述：** Populate tunnel metadata for packet associated to skb. The tunnel metadata is set to the contents of key, of size. The flags can be set to a combination of the following values: BPF_F_TUNINFO_IPV6 Indicate that the tunnel is based on IPv6 protocol...

**返回：** 0 on success, or a negative error in case of failure.

### #29 `bpf_skb_get_tunnel_opt`

```c
long bpf_skb_get_tunnel_opt(struct __sk_buff *skb, void *opt, __u32 size);
```

**描述：** Retrieve tunnel options metadata for the packet associated to skb, and store the raw tunnel option data to the buffer opt of size. This helper can be used with encapsulation devices that can operate in "collect metadata" mode (please refer to the ...

**返回：** The size of the option data retrieved.

### #30 `bpf_skb_set_tunnel_opt`

```c
long bpf_skb_set_tunnel_opt(struct __sk_buff *skb, void *opt, __u32 size);
```

**描述：** Set tunnel options metadata for the packet associated to skb to the option data contained in the raw buffer opt of size. See also the description of the bpf_skb_get_tunnel_opt\ () helper for additional information.

**返回：** 0 on success, or a negative error in case of failure.

### #73 `bpf_lwt_push_encap`

```c
long bpf_lwt_push_encap(struct __sk_buff *skb, __u32 type, void *hdr, __u32 len);
```

**描述：** Encapsulate the packet associated to skb within a Layer 3 protocol header. This header is provided in the buffer at address hdr, with len its size in bytes. type indicates the protocol of the header and can be one of: BPF_LWT_ENCAP_SEG6 IPv6 encap...

**返回：** 0 on success, or a negative error in case of failure.

### #74 `bpf_lwt_seg6_store_bytes`

```c
long bpf_lwt_seg6_store_bytes(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len);
```

**描述：** Store len bytes from address from into the packet associated to skb, at offset. Only the flags, tag and TLVs inside the outermost IPv6 Segment Routing Header can be modified through this helper. A call to this helper is susceptible to change the u...

**返回：** 0 on success, or a negative error in case of failure.

### #75 `bpf_lwt_seg6_adjust_srh`

```c
long bpf_lwt_seg6_adjust_srh(struct __sk_buff *skb, __u32 offset, __s32 delta);
```

**描述：** Adjust the size allocated to TLVs in the outermost IPv6 Segment Routing Header contained in the packet associated to skb, at position offset by delta bytes. Only offsets after the segments are accepted. delta can be as well positive (growing) as n...

**返回：** 0 on success, or a negative error in case of failure.

### #76 `bpf_lwt_seg6_action`

```c
long bpf_lwt_seg6_action(struct __sk_buff *skb, __u32 action, void *param, __u32 param_len);
```

**描述：** Apply an IPv6 Segment Routing action of type action to the packet associated to skb. Each action takes a parameter contained at address param, and of length param_len bytes. action can be one of: SEG6_LOCAL_ACTION_END_X End.X action: Endpoint with...

**返回：** 0 on success, or a negative error in case of failure.

---

## 8. 网络 — Socket / sk_msg（44 个）

### #46 `bpf_get_socket_cookie`

```c
__u64 bpf_get_socket_cookie(void *ctx);
```

**描述：** If the struct sk_buff pointed by skb has a known socket, retrieve the cookie (generated by the kernel) of this socket. If no cookie has been set yet, generate a new cookie. Once generated, the socket cookie remains stable for the life of the socke...

**返回：** A 8-byte long unique number on success, or 0 if the socket field is missing inside skb.

### #47 `bpf_get_socket_uid`

```c
__u32 bpf_get_socket_uid(struct __sk_buff *skb);
```

**描述：** Get the owner UID of the socked associated to skb.

**返回：** The owner UID of the socket associated to skb. If the socket is NULL, or if it is not a full socket (i.e. if it is a time-wait or a request socket instead), overflowuid value is returned (note that overflowuid might also be the actual UID value fo...

### #49 `bpf_setsockopt`

```c
long bpf_setsockopt(void *bpf_socket, int level, int optname, void *optval, int optlen);
```

**描述：** Emulate a call to setsockopt() on the socket associated to bpf_socket, which must be a full socket. The level at which the option resides and the name optname of the option must be specified, see setsockopt(2) for more information. The option valu...

**返回：** 0 on success, or a negative error in case of failure.

### #53 `bpf_sock_map_update`

```c
long bpf_sock_map_update(struct bpf_sock_ops *skops, void *map, void *key, __u64 flags);
```

**描述：** Add an entry to, or update a map referencing sockets. The skops is used as a new value for the entry associated to key. flags is one of: BPF_NOEXIST The entry for key must not exist in the map. BPF_EXIST The entry for key must already exist in the...

**返回：** 0 on success, or a negative error in case of failure.

### #57 `bpf_getsockopt`

```c
long bpf_getsockopt(void *bpf_socket, int level, int optname, void *optval, int optlen);
```

**描述：** Emulate a call to getsockopt() on the socket associated to bpf_socket, which must be a full socket. The level at which the option resides and the name optname of the option must be specified, see getsockopt(2) for more information. The retrieved v...

**返回：** 0 on success, or a negative error in case of failure.

### #58 `bpf_override_return`

```c
long bpf_override_return(struct pt_regs *regs, __u64 rc);
```

**描述：** Used for error injection, this helper uses kprobes to override the return value of the probed function, and to set it to rc. The first argument is the context regs on which the kprobe works. This helper works by setting the PC (program counter) to...

**返回：** 0

### #59 `bpf_sock_ops_cb_flags_set`

```c
long bpf_sock_ops_cb_flags_set(struct bpf_sock_ops *bpf_sock, int argval);
```

**描述：** Attempt to set the value of the bpf_sock_ops_cb_flags field for the full TCP socket associated to bpf_sock_ops to argval. The primary use of this field is to determine if there should be calls to eBPF programs of type BPF_PROG_TYPE_SOCK_OPS at var...

**返回：** Code -EINVAL if the socket is not a full TCP socket; otherwise, a positive number containing the bits that could not be set is returned (which comes down to 0 if all bits were set as required).

### #60 `bpf_msg_redirect_map`

```c
long bpf_msg_redirect_map(struct sk_msg_md *msg, void *map, __u32 key, __u64 flags);
```

**描述：** This helper is used in programs implementing policies at the socket level. If the message msg is allowed to pass (i.e. if the verdict eBPF program returns SK_PASS), redirect it to the socket referenced by map (of type BPF_MAP_TYPE_SOCKMAP) at inde...

**返回：** SK_PASS on success, or SK_DROP on error.

### #61 `bpf_msg_apply_bytes`

```c
long bpf_msg_apply_bytes(struct sk_msg_md *msg, __u32 bytes);
```

**描述：** For socket policies, apply the verdict of the eBPF program to the next bytes (number of bytes) of message msg. For example, this helper can be used in the following cases:  A single sendmsg\ () or sendfile\ () system call contains multiple logical...

**返回：** 0

### #62 `bpf_msg_cork_bytes`

```c
long bpf_msg_cork_bytes(struct sk_msg_md *msg, __u32 bytes);
```

**描述：** For socket policies, prevent the execution of the verdict eBPF program for message msg until bytes (byte number) have been accumulated. This can be used when one needs a specific number of bytes before a verdict can be assigned, even if the data s...

**返回：** 0

### #63 `bpf_msg_pull_data`

```c
long bpf_msg_pull_data(struct sk_msg_md *msg, __u32 start, __u32 end, __u64 flags);
```

**描述：** For socket policies, pull in non-linear data from user space for msg and set pointers msg\ ->data and msg\ ->data_end to start and end bytes offsets into msg, respectively. If a program of type BPF_PROG_TYPE_SK_MSG is run on a msg it can only pars...

**返回：** 0 on success, or a negative error in case of failure.

### #64 `bpf_bind`

```c
long bpf_bind(struct bpf_sock_addr *ctx, struct sockaddr *addr, int addr_len);
```

**描述：** Bind the socket associated to ctx to the address pointed by addr, of length addr_len. This allows for making outgoing connection from the desired IP address, which can be useful for example when all processes inside a cgroup should use one single ...

**返回：** 0 on success, or a negative error in case of failure.

### #70 `bpf_sock_hash_update`

```c
long bpf_sock_hash_update(struct bpf_sock_ops *skops, void *map, void *key, __u64 flags);
```

**描述：** Add an entry to, or update a sockhash map referencing sockets. The skops is used as a new value for the entry associated to key. flags is one of: BPF_NOEXIST The entry for key must not exist in the map. BPF_EXIST The entry for key must already exi...

**返回：** 0 on success, or a negative error in case of failure.

### #71 `bpf_msg_redirect_hash`

```c
long bpf_msg_redirect_hash(struct sk_msg_md *msg, void *map, void *key, __u64 flags);
```

**描述：** This helper is used in programs implementing policies at the socket level. If the message msg is allowed to pass (i.e. if the verdict eBPF program returns SK_PASS), redirect it to the socket referenced by map (of type BPF_MAP_TYPE_SOCKHASH) using ...

**返回：** SK_PASS on success, or SK_DROP on error.

### #72 `bpf_sk_redirect_hash`

```c
long bpf_sk_redirect_hash(struct __sk_buff *skb, void *map, void *key, __u64 flags);
```

**描述：** This helper is used in programs implementing policies at the skb socket level. If the sk_buff skb is allowed to pass (i.e. if the verdict eBPF program returns SK_PASS), redirect it to the socket referenced by map (of type BPF_MAP_TYPE_SOCKHASH) us...

**返回：** SK_PASS on success, or SK_DROP on error.

### #82 `bpf_sk_select_reuseport`

```c
long bpf_sk_select_reuseport(struct sk_reuseport_md *reuse, void *map, void *key, __u64 flags);
```

**描述：** Select a SO_REUSEPORT socket from a BPF_MAP_TYPE_REUSEPORT_SOCKARRAY map. It checks the selected socket is matching the incoming request in the socket buffer.

**返回：** 0 on success, or a negative error in case of failure.

### #84 `bpf_sock`

```c
struct bpf_sock * bpf_sk_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags);
```

**描述：** bpf_sk_lookup_tcp Look for TCP socket matching tuple, optionally in a child network namespace netns. The return value must be checked, and if non-NULL, released via bpf_sk_release\ (). The ctx should point to the context of the program, such as th...

**返回：** Pointer to struct bpf_sock, or NULL in case of failure. For sockets with reuseport option, the struct bpf_sock result is from reuse\ ->socks\ [] using the hash of the tuple.

### #85 `bpf_sock`

```c
struct bpf_sock * bpf_sk_lookup_udp(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags);
```

**描述：** bpf_sk_lookup_udp Look for UDP socket matching tuple, optionally in a child network namespace netns. The return value must be checked, and if non-NULL, released via bpf_sk_release\ (). The ctx should point to the context of the program, such as th...

**返回：** Pointer to struct bpf_sock, or NULL in case of failure. For sockets with reuseport option, the struct bpf_sock result is from reuse\ ->socks\ [] using the hash of the tuple.

### #86 `bpf_sk_release`

```c
long bpf_sk_release(void *sock);
```

**描述：** Release the reference held by sock. sock must be a non-NULL pointer that was returned from bpf_sk_lookup_xxx\ ().

**返回：** 0 on success, or a negative error in case of failure.

### #95 `bpf_sock`

```c
struct bpf_sock * bpf_sk_fullsock(struct bpf_sock *sk);
```

**描述：** bpf_sk_fullsock This helper gets a struct bpf_sock pointer such that all the fields in this bpf_sock can be accessed.

**返回：** A struct bpf_sock pointer on success, or NULL in case of failure.

### #96 `bpf_tcp_sock`

```c
struct bpf_tcp_sock * bpf_tcp_sock(struct bpf_sock *sk);
```

**描述：** This helper gets a struct bpf_tcp_sock pointer from a struct bpf_sock pointer.

**返回：** A struct bpf_tcp_sock pointer on success, or NULL in case of failure.

### #98 `bpf_sock`

```c
struct bpf_sock * bpf_get_listener_sock(struct bpf_sock *sk);
```

**描述：** bpf_get_listener_sock Return a struct bpf_sock pointer in TCP_LISTEN state. bpf_sk_release\ () is unnecessary and not allowed.

**返回：** A struct bpf_sock pointer on success, or NULL in case of failure.

### #99 `bpf_sock`

```c
struct bpf_sock * bpf_skc_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags);
```

**描述：** bpf_skc_lookup_tcp Look for TCP socket matching tuple, optionally in a child network namespace netns. The return value must be checked, and if non-NULL, released via bpf_sk_release\ (). This function is identical to bpf_sk_lookup_tcp\ (), except t...

**返回：** Pointer to struct bpf_sock, or NULL in case of failure. For sockets with reuseport option, the struct bpf_sock result is from reuse\ ->socks\ [] using the hash of the tuple.

### #100 `bpf_tcp_check_syncookie`

```c
long bpf_tcp_check_syncookie(void *sk, void *iph, __u32 iph_len, struct tcphdr *th, __u32 th_len);
```

**描述：** Check whether iph and th contain a valid SYN cookie ACK for the listening socket in sk. iph points to the start of the IPv4 or IPv6 header, while iph_len contains sizeof\ (struct iphdr) or sizeof\ (struct ipv6hdr). th points to the start of the TC...

**返回：** 0 if iph and th are a valid SYN cookie ACK, or a negative error otherwise.

### #107 `bpf_sk_storage_get`

```c
void * bpf_sk_storage_get(void *map, void *sk, void *value, __u64 flags);
```

**描述：** Get a bpf-local-storage from a sk. Logically, it could be thought of getting the value from a map with sk as the key.  From this perspective,  the usage is not much different from bpf_map_lookup_elem\ (map, &\ sk) except this helper enforces the k...

**返回：** A bpf-local-storage pointer is returned on success. NULL if not found or there was an error in adding a new bpf-local-storage.

### #108 `bpf_sk_storage_delete`

```c
long bpf_sk_storage_delete(void *map, void *sk);
```

**描述：** Delete a bpf-local-storage from a sk.

**返回：** 0 on success. -ENOENT if the bpf-local-storage cannot be found. -EINVAL if sk is not a fullsock (e.g. a request_sock).

### #116 `bpf_tcp_send_ack`

```c
long bpf_tcp_send_ack(void *tp, __u32 rcv_nxt);
```

**描述：** Send out a tcp-ack. tp is the in-kernel struct tcp_sock. rcv_nxt is the ack_seq to be sent out.

**返回：** 0 on success, or a negative error in case of failure.

### #124 `bpf_sk_assign`

```c
long bpf_sk_assign(void *ctx, void *sk, __u64 flags);
```

**描述：** Helper is overloaded depending on BPF program type. This description applies to BPF_PROG_TYPE_SCHED_CLS and BPF_PROG_TYPE_SCHED_ACT programs. Assign the sk to the skb. When combined with appropriate routing configuration to receive the packet towa...

**返回：** 0 on success, or a negative error in case of failure: -EINVAL if specified flags are not supported. -ENOENT if the socket is unavailable for assignment. -ENETUNREACH if the socket is unreachable (wrong netns). -EOPNOTSUPP if the operation is not s...

### #128 `bpf_sk_cgroup_id`

```c
__u64 bpf_sk_cgroup_id(void *sk);
```

**描述：** Return the cgroup v2 id of the socket sk. sk must be a non-NULL pointer to a socket, e.g. one returned from bpf_sk_lookup_xxx\ (), bpf_sk_fullsock\ (), etc. The format of returned id is same as in bpf_skb_cgroup_id\ (). This helper is available on...

**返回：** The id is returned or 0 in case the id could not be retrieved.

### #129 `bpf_sk_ancestor_cgroup_id`

```c
__u64 bpf_sk_ancestor_cgroup_id(void *sk, int ancestor_level);
```

**描述：** Return id of cgroup v2 that is ancestor of cgroup associated with the sk at the ancestor_level.  The root cgroup is at ancestor_level zero and each step down the hierarchy increments the level. If ancestor_level == level of cgroup associated with ...

**返回：** The id is returned or 0 in case the id could not be retrieved.

### #136 `bpf_skc_to_tcp6_sock`

```c
struct tcp6_sock * bpf_skc_to_tcp6_sock(void *sk);
```

**描述：** Dynamically cast a sk pointer to a tcp6_sock pointer.

**返回：** sk if casting is valid, or NULL otherwise.

### #137 `bpf_skc_to_tcp_sock`

```c
struct tcp_sock * bpf_skc_to_tcp_sock(void *sk);
```

**描述：** Dynamically cast a sk pointer to a tcp_sock pointer.

**返回：** sk if casting is valid, or NULL otherwise.

### #138 `bpf_skc_to_tcp_timewait_sock`

```c
struct tcp_timewait_sock * bpf_skc_to_tcp_timewait_sock(void *sk);
```

**描述：** Dynamically cast a sk pointer to a tcp_timewait_sock pointer.

**返回：** sk if casting is valid, or NULL otherwise.

### #139 `bpf_skc_to_tcp_request_sock`

```c
struct tcp_request_sock * bpf_skc_to_tcp_request_sock(void *sk);
```

**描述：** Dynamically cast a sk pointer to a tcp_request_sock pointer.

**返回：** sk if casting is valid, or NULL otherwise.

### #140 `bpf_skc_to_udp6_sock`

```c
struct udp6_sock * bpf_skc_to_udp6_sock(void *sk);
```

**描述：** Dynamically cast a sk pointer to a udp6_sock pointer.

**返回：** sk if casting is valid, or NULL otherwise.

### #142 `bpf_load_hdr_opt`

```c
long bpf_load_hdr_opt(struct bpf_sock_ops *skops, void *searchby_res, __u32 len, __u64 flags);
```

**描述：** Load header option.  Support reading a particular TCP header option for bpf program (BPF_PROG_TYPE_SOCK_OPS). If flags is 0, it will search the option from the skops\ ->skb_data.  The comment in struct bpf_sock_ops has details on what skb_data con...

**返回：** > 0 when found, the header option is copied to searchby_res. The return value is the total length copied. On failure, a negative error code is returned: -EINVAL if a parameter is invalid. -ENOMSG if the option is not found. -ENOENT if no syn packe...

### #143 `bpf_store_hdr_opt`

```c
long bpf_store_hdr_opt(struct bpf_sock_ops *skops, const void *from, __u32 len, __u64 flags);
```

**描述：** Store header option.  The data will be copied from buffer from with length len to the TCP header. The buffer from should have the whole option that includes the kind, kind-length, and the actual option data.  The len must be at least kind-length l...

**返回：** 0 on success, or negative error in case of failure: -EINVAL If param is invalid. -ENOSPC if there is not enough space in the header. Nothing has been written -EEXIST if the option already exists. -EFAULT on failure to parse the existing header opt...

### #144 `bpf_reserve_hdr_opt`

```c
long bpf_reserve_hdr_opt(struct bpf_sock_ops *skops, __u32 len, __u64 flags);
```

**描述：** Reserve len bytes for the bpf header option.  The space will be used by bpf_store_hdr_opt\ () later in BPF_SOCK_OPS_WRITE_HDR_OPT_CB. If bpf_reserve_hdr_opt\ () is called multiple times, the total number of bytes will be reserved. This helper can ...

**返回：** 0 on success, or negative error in case of failure: -EINVAL if a parameter is invalid. -ENOSPC if there is not enough space in the header. -EPERM if the helper cannot be used under the current skops\ ->op.

### #178 `bpf_skc_to_unix_sock`

```c
struct unix_sock * bpf_skc_to_unix_sock(void *sk);
```

**描述：** Dynamically cast a sk pointer to a unix_sock pointer.

**返回：** sk if casting is valid, or NULL otherwise.

### #196 `bpf_skc_to_mptcp_sock`

```c
struct mptcp_sock * bpf_skc_to_mptcp_sock(void *sk);
```

**描述：** Dynamically cast a sk pointer to a mptcp_sock pointer.

**返回：** sk if casting is valid, or NULL otherwise.

### #204 `bpf_tcp_raw_gen_syncookie_ipv4`

```c
__s64 bpf_tcp_raw_gen_syncookie_ipv4(struct iphdr *iph, struct tcphdr *th, __u32 th_len);
```

**描述：** Try to issue a SYN cookie for the packet with corresponding IPv4/TCP headers, iph and th, without depending on a listening socket. iph points to the IPv4 header. th points to the start of the TCP header, while th_len contains the length of the TCP...

**返回：** On success, lower 32 bits hold the generated SYN cookie in followed by 16 bits which hold the MSS value for that cookie, and the top 16 bits are unused. On failure, the returned value is one of the following: -EINVAL if th_len is invalid.

### #205 `bpf_tcp_raw_gen_syncookie_ipv6`

```c
__s64 bpf_tcp_raw_gen_syncookie_ipv6(struct ipv6hdr *iph, struct tcphdr *th, __u32 th_len);
```

**描述：** Try to issue a SYN cookie for the packet with corresponding IPv6/TCP headers, iph and th, without depending on a listening socket. iph points to the IPv6 header. th points to the start of the TCP header, while th_len contains the length of the TCP...

**返回：** On success, lower 32 bits hold the generated SYN cookie in followed by 16 bits which hold the MSS value for that cookie, and the top 16 bits are unused. On failure, the returned value is one of the following: -EINVAL if th_len is invalid. -EPROTON...

### #206 `bpf_tcp_raw_check_syncookie_ipv4`

```c
long bpf_tcp_raw_check_syncookie_ipv4(struct iphdr *iph, struct tcphdr *th);
```

**描述：** Check whether iph and th contain a valid SYN cookie ACK without depending on a listening socket. iph points to the IPv4 header. th points to the TCP header.

**返回：** 0 if iph and th are a valid SYN cookie ACK. On failure, the returned value is one of the following: -EACCES if the SYN cookie is not valid.

### #207 `bpf_tcp_raw_check_syncookie_ipv6`

```c
long bpf_tcp_raw_check_syncookie_ipv6(struct ipv6hdr *iph, struct tcphdr *th);
```

**描述：** Check whether iph and th contain a valid SYN cookie ACK without depending on a listening socket. iph points to the IPv6 header. th points to the TCP header.

**返回：** 0 if iph and th are a valid SYN cookie ACK. On failure, the returned value is one of the following: -EACCES if the SYN cookie is not valid. -EPROTONOSUPPORT if CONFIG_IPV6 is not builtin.

---

## 9. 网络 — VLAN（2 个）

### #18 `bpf_skb_vlan_push`

```c
long bpf_skb_vlan_push(struct __sk_buff *skb, __be16 vlan_proto, __u16 vlan_tci);
```

**描述：** Push a vlan_tci (VLAN tag control information) of protocol vlan_proto to the packet associated to skb, then update the checksum. Note that if vlan_proto is different from ETH_P_8021Q and ETH_P_8021AD, it is considered to be ETH_P_8021Q. A call to ...

**返回：** 0 on success, or a negative error in case of failure.

### #19 `bpf_skb_vlan_pop`

```c
long bpf_skb_vlan_pop(struct __sk_buff *skb);
```

**描述：** Pop a VLAN header from the packet associated to skb. A call to this helper is susceptible to change the underlying packet buffer. Therefore, at load time, all checks on pointers previously done by the verifier are invalidated and must be performed...

**返回：** 0 on success, or a negative error in case of failure.

---

## 10. 网络 — XDP 专用（4 个）

### #44 `bpf_xdp_adjust_head`

```c
long bpf_xdp_adjust_head(struct xdp_md *xdp_md, int delta);
```

**描述：** Adjust (move) xdp_md\ ->data by delta bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying pa...

**返回：** 0 on success, or a negative error in case of failure.

### #54 `bpf_xdp_adjust_meta`

```c
long bpf_xdp_adjust_meta(struct xdp_md *xdp_md, int delta);
```

**描述：** Adjust the address pointed by xdp_md\ ->data_meta by delta (which can be positive or negative). Note that this operation modifies the address stored in xdp_md\ ->data, so the latter must be loaded only after the helper has been called. The use of ...

**返回：** 0 on success, or a negative error in case of failure.

### #65 `bpf_xdp_adjust_tail`

```c
long bpf_xdp_adjust_tail(struct xdp_md *xdp_md, int delta);
```

**描述：** Adjust (move) xdp_md\ ->data_end by delta bytes. It is possible to both shrink and grow the packet tail. Shrink done via delta being a negative integer. A call to this helper is susceptible to change the underlying packet buffer. Therefore, at loa...

**返回：** 0 on success, or a negative error in case of failure.

### #121 `bpf_xdp_output`

```c
long bpf_xdp_output(void *ctx, void *map, __u64 flags, void *data, __u64 size);
```

**描述：** Write raw data blob into a special BPF perf event held by map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY. This perf event must have the following attributes: PERF_SAMPLE_RAW as sample_type, PERF_TYPE_SOFTWARE as type, and PERF_COUNT_SW_BPF_OUTPUT as co...

**返回：** 0 on success, or a negative error in case of failure.

---

## 11. 网络 — SKB 杂项（10 个）

### #17 `bpf_get_cgroup_classid`

```c
__u32 bpf_get_cgroup_classid(struct __sk_buff *skb);
```

**描述：** Retrieve the classid for the current task, i.e. for the net_cls cgroup to which skb belongs. This helper can be used on TC egress path, but not on ingress. The net_cls cgroup provides an interface to tag network packets based on a user-provided id...

**返回：** The classid, or 0 for the default unconfigured classid.

### #24 `bpf_get_route_realm`

```c
__u32 bpf_get_route_realm(struct __sk_buff *skb);
```

**描述：** Retrieve the realm or the route, that is to say the tclassid field of the destination for the skb. The identifier retrieved is a user-provided tag, similar to the one used with the net_cls cgroup (see description for bpf_get_cgroup_classid\ () hel...

**返回：** The realm of the route for the packet associated to skb, or 0 if none was found.

### #33 `bpf_skb_under_cgroup`

```c
long bpf_skb_under_cgroup(struct __sk_buff *skb, void *map, __u32 index);
```

**描述：** Check whether skb is a descendant of the cgroup2 held by map of type BPF_MAP_TYPE_CGROUP_ARRAY, at index.

**返回：** The return value depends on the result of the test, and can be:  0, if the skb failed the cgroup2 descendant test.  1, if the skb succeeded the cgroup2 descendant test.  A negative error code, if an error occurred.

### #34 `bpf_get_hash_recalc`

```c
__u32 bpf_get_hash_recalc(struct __sk_buff *skb);
```

**描述：** Retrieve the hash of the packet, skb\ ->hash. If it is not set, in particular if the hash was cleared due to mangling, recompute this hash. Later accesses to the hash can be done directly with skb\ ->hash. Calling bpf_set_hash_invalid\ (), changin...

**返回：** The 32-bit hash.

### #66 `bpf_skb_get_xfrm_state`

```c
long bpf_skb_get_xfrm_state(struct __sk_buff *skb, __u32 index, struct bpf_xfrm_state *xfrm_state, __u32 size, __u64 flags);
```

**描述：** Retrieve the XFRM state (IP transform framework, see also ip-xfrm(8)) at index in XFRM "security path" for skb. The retrieved value is stored in the struct bpf_xfrm_state pointed by xfrm_state and of length size. All values for flags are reserved ...

**返回：** 0 on success, or a negative error in case of failure.

### #79 `bpf_skb_cgroup_id`

```c
__u64 bpf_skb_cgroup_id(struct __sk_buff *skb);
```

**描述：** Return the cgroup v2 id of the socket associated with the skb. This is roughly similar to the bpf_get_cgroup_classid\ () helper for cgroup v1 by providing a tag resp. identifier that can be matched on or used for map lookups e.g. to implement poli...

**返回：** The id is returned or 0 in case the id could not be retrieved.

### #83 `bpf_skb_ancestor_cgroup_id`

```c
__u64 bpf_skb_ancestor_cgroup_id(struct __sk_buff *skb, int ancestor_level);
```

**描述：** Return id of cgroup v2 that is ancestor of cgroup associated with the skb at the ancestor_level.  The root cgroup is at ancestor_level zero and each step down the hierarchy increments the level. If ancestor_level == level of cgroup associated with...

**返回：** The id is returned or 0 in case the id could not be retrieved.

### #110 `bpf_tcp_gen_syncookie`

```c
__s64 bpf_tcp_gen_syncookie(void *sk, void *iph, __u32 iph_len, struct tcphdr *th, __u32 th_len);
```

**描述：** Try to issue a SYN cookie for the packet with corresponding IP/TCP headers, iph and th, on the listening socket in sk. iph points to the start of the IPv4 or IPv6 header, while iph_len contains sizeof\ (struct iphdr) or sizeof\ (struct ipv6hdr). t...

**返回：** On success, lower 32 bits hold the generated SYN cookie in followed by 16 bits which hold the MSS value for that cookie, and the top 16 bits are unused. On failure, the returned value is one of the following: -EINVAL SYN cookie cannot be issued du...

### #151 `bpf_skb_cgroup_classid`

```c
__u64 bpf_skb_cgroup_classid(struct __sk_buff *skb);
```

**描述：** See bpf_get_cgroup_classid\ () for the main description. This helper differs from bpf_get_cgroup_classid\ () in that the cgroup v1 net_cls class is retrieved only from the skb's associated socket instead of the current process.

**返回：** The id is returned or 0 in case the id could not be retrieved.

### #193 `bpf_ima_file_hash`

```c
long bpf_ima_file_hash(struct file *file, void *dst, __u32 size);
```

**描述：** 

**返回：** If the hash is larger than size, then only size bytes will be copied to dst The hash_algo is returned on success, -EOPNOTSUPP if the hash calculation failed or -EINVAL if invalid arguments are passed.

---

## 12. Cgroup（6 个）

### #37 `bpf_current_task_under_cgroup`

```c
long bpf_current_task_under_cgroup(void *map, __u32 index);
```

**描述：** Check whether the probe is being run is the context of a given subset of the cgroup2 hierarchy. The cgroup2 to test is held by map of type BPF_MAP_TYPE_CGROUP_ARRAY, at index.

**返回：** The return value depends on the result of the test, and can be:  1, if current task belongs to the cgroup2.  0, if current task does not belong to the cgroup2.  A negative error code, if an error occurred.

### #80 `bpf_get_current_cgroup_id`

```c
__u64 bpf_get_current_cgroup_id(void);
```

**描述：** Get the current cgroup id based on the cgroup within which the current task is running.

**返回：** A 64-bit integer containing the current cgroup id based on the cgroup within which the current task is running.

### #122 `bpf_get_netns_cookie`

```c
__u64 bpf_get_netns_cookie(void *ctx);
```

**描述：** Retrieve the cookie (generated by the kernel) of the network namespace the input ctx is associated with. The network namespace cookie remains stable for its lifetime and provides a global identifier that can be assumed unique. If ctx is NULL, then...

**返回：** A 8-byte long opaque number.

### #123 `bpf_get_current_ancestor_cgroup_id`

```c
__u64 bpf_get_current_ancestor_cgroup_id(int ancestor_level);
```

**描述：** Return id of cgroup v2 that is ancestor of the cgroup associated with the current task at the ancestor_level. The root cgroup is at ancestor_level zero and each step down the hierarchy increments the level. If ancestor_level == level of cgroup ass...

**返回：** The id is returned or 0 in case the id could not be retrieved.

### #210 `bpf_cgrp_storage_get`

```c
void * bpf_cgrp_storage_get(void *map, struct cgroup *cgroup, void *value, __u64 flags);
```

**描述：** Get a bpf_local_storage from the cgroup. Logically, it could be thought of as getting the value from a map with cgroup as the key.  From this perspective,  the usage is not much different from bpf_map_lookup_elem\ (map, &\ cgroup) except this help...

**返回：** A bpf_local_storage pointer is returned on success. NULL if not found or there was an error in adding a new bpf_local_storage.

### #211 `bpf_cgrp_storage_delete`

```c
long bpf_cgrp_storage_delete(void *map, struct cgroup *cgroup);
```

**描述：** Delete a bpf_local_storage from a cgroup.

**返回：** 0 on success. -ENOENT if the bpf_local_storage cannot be found.

---

## 13. Perf / Ring Buffer（14 个）

### #22 `bpf_perf_event_read`

```c
__u64 bpf_perf_event_read(void *map, __u64 flags);
```

**描述：** Read the value of a perf event counter. This helper relies on a map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY. The nature of the perf event counter is selected when map is updated with perf event file descriptors. The map is an array whose size is the...

**返回：** The value of the perf event counter read from the map, or a negative error code in case of failure.

### #25 `bpf_perf_event_output`

```c
long bpf_perf_event_output(void *ctx, void *map, __u64 flags, void *data, __u64 size);
```

**描述：** Write raw data blob into a special BPF perf event held by map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY. This perf event must have the following attributes: PERF_SAMPLE_RAW as sample_type, PERF_TYPE_SOFTWARE as type, and PERF_COUNT_SW_BPF_OUTPUT as co...

**返回：** 0 on success, or a negative error in case of failure.

### #55 `bpf_perf_event_read_value`

```c
long bpf_perf_event_read_value(void *map, __u64 flags, struct bpf_perf_event_value *buf, __u32 buf_size);
```

**描述：** Read the value of a perf event counter, and store it into buf of size buf_size. This helper relies on a map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY. The nature of the perf event counter is selected when map is updated with perf event file descriptor...

**返回：** 0 on success, or a negative error in case of failure.

### #56 `bpf_perf_prog_read_value`

```c
long bpf_perf_prog_read_value(struct bpf_perf_event_data *ctx, struct bpf_perf_event_value *buf, __u32 buf_size);
```

**描述：** For an eBPF program attached to a perf event, retrieve the value of the event counter associated to ctx and store it in the structure pointed by buf and of size buf_size. Enabled and running times are also stored in the structure (see description ...

**返回：** 0 on success, or a negative error in case of failure.

### #110 `bpf_tcp_gen_syncookie`

```c
__s64 bpf_tcp_gen_syncookie(void *sk, void *iph, __u32 iph_len, struct tcphdr *th, __u32 th_len);
```

**描述：** Try to issue a SYN cookie for the packet with corresponding IP/TCP headers, iph and th, on the listening socket in sk. iph points to the start of the IPv4 or IPv6 header, while iph_len contains sizeof\ (struct iphdr) or sizeof\ (struct ipv6hdr). t...

**返回：** On success, lower 32 bits hold the generated SYN cookie in followed by 16 bits which hold the MSS value for that cookie, and the top 16 bits are unused. On failure, the returned value is one of the following: -EINVAL SYN cookie cannot be issued du...

### #130 `bpf_ringbuf_output`

```c
long bpf_ringbuf_output(void *ringbuf, void *data, __u64 size, __u64 flags);
```

**描述：** Copy size bytes from data into a ring buffer ringbuf. If BPF_RB_NO_WAKEUP is specified in flags, no notification of new data availability is sent. If BPF_RB_FORCE_WAKEUP is specified in flags, notification of new data availability is sent uncondit...

**返回：** 0 on success, or a negative error in case of failure.

### #131 `bpf_ringbuf_reserve`

```c
void * bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags);
```

**描述：** Reserve size bytes of payload in a ring buffer ringbuf. flags must be 0.

**返回：** Valid pointer with size bytes of memory available; NULL, otherwise.

### #132 `bpf_ringbuf_submit`

```c
void bpf_ringbuf_submit(void *data, __u64 flags);
```

**描述：** Submit reserved ring buffer sample, pointed to by data. If BPF_RB_NO_WAKEUP is specified in flags, no notification of new data availability is sent. If BPF_RB_FORCE_WAKEUP is specified in flags, notification of new data availability is sent uncond...

**返回：** Nothing. Always succeeds.

### #133 `bpf_ringbuf_discard`

```c
void bpf_ringbuf_discard(void *data, __u64 flags);
```

**描述：** Discard reserved ring buffer sample, pointed to by data. If BPF_RB_NO_WAKEUP is specified in flags, no notification of new data availability is sent. Discarded records remain in the ring buffer until consumed by user space, so a later submit using...

**返回：** Nothing. Always succeeds.

### #134 `bpf_ringbuf_query`

```c
__u64 bpf_ringbuf_query(void *ringbuf, __u64 flags);
```

**描述：** Query various characteristics of provided ring buffer. What exactly is queries is determined by flags:  BPF_RB_AVAIL_DATA: Amount of data not yet consumed.  BPF_RB_RING_SIZE: The size of ring buffer.  BPF_RB_CONS_POS: Consumer position (can wrap a...

**返回：** Requested value, or 0, if flags are not recognized.

### #198 `bpf_ringbuf_reserve_dynptr`

```c
long bpf_ringbuf_reserve_dynptr(void *ringbuf, __u32 size, __u64 flags, struct bpf_dynptr *ptr);
```

**描述：** Reserve size bytes of payload in a ring buffer ringbuf through the dynptr interface. flags must be 0. Please note that a corresponding bpf_ringbuf_submit_dynptr or bpf_ringbuf_discard_dynptr must be called on ptr, even if the reservation fails. Th...

**返回：** 0 on success, or a negative error in case of failure.

### #199 `bpf_ringbuf_submit_dynptr`

```c
void bpf_ringbuf_submit_dynptr(struct bpf_dynptr *ptr, __u64 flags);
```

**描述：** Submit reserved ring buffer sample, pointed to by data, through the dynptr interface. This is a no-op if the dynptr is invalid/null. For more information on flags, please see 'bpf_ringbuf_submit'.

**返回：** Nothing. Always succeeds.

### #200 `bpf_ringbuf_discard_dynptr`

```c
void bpf_ringbuf_discard_dynptr(struct bpf_dynptr *ptr, __u64 flags);
```

**描述：** Discard reserved ring buffer sample through the dynptr interface. This is a no-op if the dynptr is invalid/null. For more information on flags, please see 'bpf_ringbuf_discard'.

**返回：** Nothing. Always succeeds.

### #209 `bpf_user_ringbuf_drain`

```c
long bpf_user_ringbuf_drain(void *map, void *callback_fn, void *ctx, __u64 flags);
```

**描述：** Drain samples from the specified user ring buffer, and invoke the provided callback for each such sample: long (\callback_fn)(const struct bpf_dynptr \dynptr, void \ctx); If callback_fn returns 0, the helper will continue to try and drain the next...

**返回：** The number of drained samples if no error was encountered while draining samples, or 0 if no samples were present in the ring buffer. If a user-space producer was epoll-waiting on this map, and at least one sample was drained, they will receive an...

---

## 14. 系统 / 内核信息（3 个）

### #7 `bpf_get_prandom_u32`

```c
__u32 bpf_get_prandom_u32(void);
```

**描述：** Get a pseudo-random number. From a security point of view, this helper uses its own pseudo-random internal state, and cannot be used to infer the seed of other random functions in the kernel. However, it is essential to note that the generator use...

**返回：** A random 32-bit unsigned value.

### #8 `bpf_fastcall`

```c
__bpf_fastcall __u32 (* const bpf_get_smp_processor_id)(void);
```

**描述：** bpf_get_smp_processor_id Get the SMP (symmetric multiprocessing) processor id. Note that all programs run with migration disabled, which means that the SMP processor id is stable during all the execution of the program.

**返回：** The SMP id of the processor running the program.

### #42 `bpf_get_numa_node_id`

```c
long bpf_get_numa_node_id(void);
```

**描述：** Return the id of the current NUMA node. The primary use case for this helper is the selection of sockets for the local NUMA node, when the program is attached to sockets using the SO_ATTACH_REUSEPORT_EBPF option (see also socket(7)), but the helpe...

**返回：** The id of current NUMA node.

---

## 15. Tail Call / 程序链接（2 个）

### #12 `bpf_tail_call`

```c
long bpf_tail_call(void *ctx, void *prog_array_map, __u32 index);
```

**描述：** This special helper is used to trigger a "tail call", or in other words, to jump into another eBPF program. The same stack frame is used (but values on stack and in registers for the caller are not accessible to the callee). This mechanism allows ...

**返回：** 0 on success, or a negative error in case of failure.

### #174 `bpf_get_attach_cookie`

```c
__u64 bpf_get_attach_cookie(void *ctx);
```

**描述：** Get bpf_cookie value provided (optionally) during the program attachment. It might be different for each individual attachment, even if BPF program itself is the same. Expects BPF program context ctx as a first argument. Supported for the followin...

**返回：** Value specified by user at BPF link creation/attachment time or 0, if it was not specified.

---

## 16. Sysctl（6 个）

### #101 `bpf_sysctl_get_name`

```c
long bpf_sysctl_get_name(struct bpf_sysctl *ctx, char *buf, unsigned long buf_len, __u64 flags);
```

**描述：** Get name of sysctl in /proc/sys/ and copy it into provided by program buffer buf of size buf_len. The buffer is always NUL terminated, unless it's zero-sized. If flags is zero, full name (e.g. "net/ipv4/tcp_mem") is copied. Use BPF_F_SYSCTL_BASE_N...

**返回：** Number of character copied (not including the trailing NUL). -E2BIG if the buffer wasn't big enough (buf will contain truncated name in this case).

### #102 `bpf_sysctl_get_current_value`

```c
long bpf_sysctl_get_current_value(struct bpf_sysctl *ctx, char *buf, unsigned long buf_len);
```

**描述：** Get current value of sysctl as it is presented in /proc/sys (incl. newline, etc), and copy it as a string into provided by program buffer buf of size buf_len. The whole value is copied, no matter what file position user space issued e.g. sys_read ...

**返回：** Number of character copied (not including the trailing NUL). -E2BIG if the buffer wasn't big enough (buf will contain truncated name in this case). -EINVAL if current value was unavailable, e.g. because sysctl is uninitialized and read returns -EI...

### #103 `bpf_sysctl_get_new_value`

```c
long bpf_sysctl_get_new_value(struct bpf_sysctl *ctx, char *buf, unsigned long buf_len);
```

**描述：** Get new value being written by user space to sysctl (before the actual write happens) and copy it as a string into provided by program buffer buf of size buf_len. User space may write new value at file position > 0. The buffer is always NUL termin...

**返回：** Number of character copied (not including the trailing NUL). -E2BIG if the buffer wasn't big enough (buf will contain truncated name in this case). -EINVAL if sysctl is being read.

### #104 `bpf_sysctl_set_new_value`

```c
long bpf_sysctl_set_new_value(struct bpf_sysctl *ctx, const char *buf, unsigned long buf_len);
```

**描述：** Override new value being written by user space to sysctl with value provided by program in buffer buf of size buf_len. buf should contain a string in same form as provided by user space on sysctl write. User space may write new value at file posit...

**返回：** 0 on success. -E2BIG if the buf_len is too big. -EINVAL if sysctl is being read.

### #105 `bpf_strtol`

```c
long bpf_strtol(const char *buf, unsigned long buf_len, __u64 flags, long *res);
```

**描述：** Convert the initial part of the string from buffer buf of size buf_len to a long integer according to the given base and save the result in res. The string may begin with an arbitrary amount of white space (as determined by isspace\ (3)) followed ...

**返回：** Number of characters consumed on success. Must be positive but no more than buf_len. -EINVAL if no valid digits were found or unsupported base was provided. -ERANGE if resulting value was out of range.

### #106 `bpf_strtoul`

```c
long bpf_strtoul(const char *buf, unsigned long buf_len, __u64 flags, unsigned long *res);
```

**描述：** Convert the initial part of the string from buffer buf of size buf_len to an unsigned long integer according to the given base and save the result in res. The string may begin with an arbitrary amount of white space (as determined by isspace\ (3))...

**返回：** Number of characters consumed on success. Must be positive but no more than buf_len. -EINVAL if no valid digits were found or unsupported base was provided. -ERANGE if resulting value was out of range.

---

## 17. 信号（2 个）

### #109 `bpf_send_signal`

```c
long bpf_send_signal(__u32 sig);
```

**描述：** Send signal sig to the process of the current task. The signal may be delivered to any of this process's threads.

**返回：** 0 on success or successfully queued. -EBUSY if work queue under nmi is full. -EINVAL if sig is invalid. -EPERM if no permission to send the sig. -EAGAIN if bpf program can try again.

### #117 `bpf_send_signal_thread`

```c
long bpf_send_signal_thread(__u32 sig);
```

**描述：** Send signal sig to the thread corresponding to the current task.

**返回：** 0 on success or successfully queued. -EBUSY if work queue under nmi is full. -EINVAL if sig is invalid. -EPERM if no permission to send the sig. -EAGAIN if bpf program can try again.

---

## 18. 定时器（4 个）

### #169 `bpf_timer_init`

```c
long bpf_timer_init(struct bpf_timer *timer, void *map, __u64 flags);
```

**描述：** Initialize the timer. First 4 bits of flags specify clockid. Only CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_BOOTTIME are allowed. All other bits of flags are reserved. The verifier will reject the program if timer is not from the same map.

**返回：** 0 on success. -EBUSY if timer is already initialized. -EINVAL if invalid flags are passed. -EPERM if timer is in a map that doesn't have any user references. The user space should either hold a file descriptor to a map with timers or pin such map ...

### #170 `bpf_timer_set_callback`

```c
long bpf_timer_set_callback(struct bpf_timer *timer, void *callback_fn);
```

**描述：** Configure the timer to call callback_fn static function.

**返回：** 0 on success. -EINVAL if timer was not initialized with bpf_timer_init() earlier. -EPERM if timer is in a map that doesn't have any user references. The user space should either hold a file descriptor to a map with timers or pin such map in bpffs....

### #171 `bpf_timer_start`

```c
long bpf_timer_start(struct bpf_timer *timer, __u64 nsecs, __u64 flags);
```

**描述：** Set timer expiration N nanoseconds from the current time. The configured callback will be invoked in soft irq context on some cpu and will not repeat unless another bpf_timer_start() is made. In such case the next invocation can migrate to a diffe...

**返回：** 0 on success. -EINVAL if timer was not initialized with bpf_timer_init() earlier or invalid flags are passed.

### #172 `bpf_timer_cancel`

```c
long bpf_timer_cancel(struct bpf_timer *timer);
```

**描述：** Cancel the timer and wait for callback_fn to finish if it was running.

**返回：** 0 if the timer was not active. 1 if the timer was active. -EINVAL if timer was not initialized with bpf_timer_init() earlier. -EDEADLK if callback_fn tried to call bpf_timer_cancel() on its own timer which would have led to a deadlock otherwise.

---

## 19. 锁 / 同步（2 个）

### #93 `bpf_spin_lock`

```c
long bpf_spin_lock(struct bpf_spin_lock *lock);
```

**描述：** Acquire a spinlock represented by the pointer lock, which is stored as part of a value of a map. Taking the lock allows to safely update the rest of the fields in that value. The spinlock can (and must) later be released with a call to bpf_spin_un...

**返回：** 0

### #94 `bpf_spin_unlock`

```c
long bpf_spin_unlock(struct bpf_spin_lock *lock);
```

**描述：** Release the lock previously locked by a call to bpf_spin_lock\ (\ lock\ ).

**返回：** 0

---

## 20. BPF 核心 / 迭代器 / 格式化（8 个）

### #126 `bpf_seq_printf`

```c
long bpf_seq_printf(struct seq_file *m, const char *fmt, __u32 fmt_size, const void *data, __u32 data_len);
```

**描述：** bpf_seq_printf\ () uses seq_file seq_printf\ () to print out the format string. The m represents the seq_file. The fmt and fmt_size are for the format string itself. The data and data_len are format string arguments. The data are a u64 array and c...

**返回：** 0 on success, or a negative error in case of failure: -EBUSY if per-CPU memory copy buffer is busy, can try again by returning 1 from bpf program. -EINVAL if arguments are invalid, or if fmt is invalid/unsupported. -E2BIG if fmt contains too many ...

### #127 `bpf_seq_write`

```c
long bpf_seq_write(struct seq_file *m, const void *data, __u32 len);
```

**描述：** bpf_seq_write\ () uses seq_file seq_write\ () to write the data. The m represents the seq_file. The data and len represent the data to write in bytes.

**返回：** 0 on success, or a negative error in case of failure: -EOVERFLOW if an overflow happened: The same object will be tried again.

### #148 `bpf_copy_from_user`

```c
long bpf_copy_from_user(void *dst, __u32 size, const void *user_ptr);
```

**描述：** Read size bytes from user space address user_ptr and store the data in dst. This is a wrapper of copy_from_user\ ().

**返回：** 0 on success, or a negative error in case of failure.

### #150 `bpf_seq_printf_btf`

```c
long bpf_seq_printf_btf(struct seq_file *m, struct btf_ptr *ptr, __u32 ptr_size, __u64 flags);
```

**描述：** Use BTF to write to seq_write a string representation of ptr->ptr, using ptr->type_id as per bpf_snprintf_btf(). flags are identical to those used for bpf_snprintf_btf.

**返回：** 0 on success or a negative error in case of failure.

### #166 `bpf_sys_bpf`

```c
long bpf_sys_bpf(__u32 cmd, void *attr, __u32 attr_size);
```

**描述：** Execute bpf syscall with given arguments.

**返回：** A syscall result.

### #167 `bpf_btf_find_by_name_kind`

```c
long bpf_btf_find_by_name_kind(char *name, int name_sz, __u32 kind, int flags);
```

**描述：** Find BTF type with given name and kind in vmlinux BTF or in module's BTFs.

**返回：** 

### #168 `bpf_sys_close`

```c
long bpf_sys_close(__u32 fd);
```

**描述：** Execute close syscall for given FD.

**返回：** A syscall result.

### #181 `bpf_loop`

```c
long bpf_loop(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags);
```

**描述：** For nr_loops, call callback_fn function with callback_ctx as the context parameter. The callback_fn should be a static function and the callback_ctx should be a pointer to the stack. The flags is used to control certain aspects of the helper. Curr...

**返回：** The number of loops performed, -EINVAL for invalid flags, -E2BIG if nr_loops exceeds the maximum number of loops.

---

## 21. 动态指针 (Dynptr)（7 个）

### #197 `bpf_dynptr_from_mem`

```c
long bpf_dynptr_from_mem(void *data, __u64 size, __u64 flags, struct bpf_dynptr *ptr);
```

**描述：** Get a dynptr to local memory data. data must be a ptr to a map value. The maximum size supported is DYNPTR_MAX_SIZE. flags is currently unused.

**返回：** 0 on success, -E2BIG if the size exceeds DYNPTR_MAX_SIZE, -EINVAL if flags is not 0.

### #198 `bpf_ringbuf_reserve_dynptr`

```c
long bpf_ringbuf_reserve_dynptr(void *ringbuf, __u32 size, __u64 flags, struct bpf_dynptr *ptr);
```

**描述：** Reserve size bytes of payload in a ring buffer ringbuf through the dynptr interface. flags must be 0. Please note that a corresponding bpf_ringbuf_submit_dynptr or bpf_ringbuf_discard_dynptr must be called on ptr, even if the reservation fails. Th...

**返回：** 0 on success, or a negative error in case of failure.

### #199 `bpf_ringbuf_submit_dynptr`

```c
void bpf_ringbuf_submit_dynptr(struct bpf_dynptr *ptr, __u64 flags);
```

**描述：** Submit reserved ring buffer sample, pointed to by data, through the dynptr interface. This is a no-op if the dynptr is invalid/null. For more information on flags, please see 'bpf_ringbuf_submit'.

**返回：** Nothing. Always succeeds.

### #200 `bpf_ringbuf_discard_dynptr`

```c
void bpf_ringbuf_discard_dynptr(struct bpf_dynptr *ptr, __u64 flags);
```

**描述：** Discard reserved ring buffer sample through the dynptr interface. This is a no-op if the dynptr is invalid/null. For more information on flags, please see 'bpf_ringbuf_discard'.

**返回：** Nothing. Always succeeds.

### #201 `bpf_dynptr_read`

```c
long bpf_dynptr_read(void *dst, __u64 len, const struct bpf_dynptr *src, __u64 offset, __u64 flags);
```

**描述：** Read len bytes from src into dst, starting from offset into src. flags is currently unused.

**返回：** 0 on success, -E2BIG if offset + len exceeds the length of src's data, -EINVAL if src is an invalid dynptr or if flags is not 0.

### #202 `bpf_dynptr_write`

```c
long bpf_dynptr_write(const struct bpf_dynptr *dst, __u64 offset, void *src, __u64 len, __u64 flags);
```

**描述：** Write len bytes from src into dst, starting from offset into dst. flags must be 0 except for skb-type dynptrs. For skb-type dynptrs:   All data slices of the dynptr are automatically invalidated after bpf_dynptr_write\ (). This is because writing ...

**返回：** 0 on success, -E2BIG if offset + len exceeds the length of dst's data, -EINVAL if dst is an invalid dynptr or if dst is a read-only dynptr or if flags is not correct. For skb-type dynptrs, other errors correspond to errors returned by bpf_skb_stor...

### #203 `bpf_dynptr_data`

```c
void * bpf_dynptr_data(const struct bpf_dynptr *ptr, __u64 offset, __u64 len);
```

**描述：** Get a pointer to the underlying dynptr data. len must be a statically known value. The returned data slice is invalidated whenever the dynptr is invalidated. skb and xdp type dynptrs may not use bpf_dynptr_data. They should instead use bpf_dynptr_...

**返回：** Pointer to the underlying dynptr data, NULL if the dynptr is read-only, if the dynptr is invalid, or if the offset and length is out of bounds.

---

## 22. 本地存储（9 个）

### #81 `bpf_get_local_storage`

```c
void * bpf_get_local_storage(void *map, __u64 flags);
```

**描述：** Get the pointer to the local storage area. The type and the size of the local storage is defined by the map argument. The flags meaning is specific for each map type, and has to be 0 for cgroup local storage. Depending on the BPF program type, a l...

**返回：** A pointer to the local storage area.

### #107 `bpf_sk_storage_get`

```c
void * bpf_sk_storage_get(void *map, void *sk, void *value, __u64 flags);
```

**描述：** Get a bpf-local-storage from a sk. Logically, it could be thought of getting the value from a map with sk as the key.  From this perspective,  the usage is not much different from bpf_map_lookup_elem\ (map, &\ sk) except this helper enforces the k...

**返回：** A bpf-local-storage pointer is returned on success. NULL if not found or there was an error in adding a new bpf-local-storage.

### #108 `bpf_sk_storage_delete`

```c
long bpf_sk_storage_delete(void *map, void *sk);
```

**描述：** Delete a bpf-local-storage from a sk.

**返回：** 0 on success. -ENOENT if the bpf-local-storage cannot be found. -EINVAL if sk is not a fullsock (e.g. a request_sock).

### #145 `bpf_inode_storage_get`

```c
void * bpf_inode_storage_get(void *map, void *inode, void *value, __u64 flags);
```

**描述：** Get a bpf_local_storage from an inode. Logically, it could be thought of as getting the value from a map with inode as the key.  From this perspective,  the usage is not much different from bpf_map_lookup_elem\ (map, &\ inode) except this helper e...

**返回：** A bpf_local_storage pointer is returned on success. NULL if not found or there was an error in adding a new bpf_local_storage.

### #146 `bpf_inode_storage_delete`

```c
int bpf_inode_storage_delete(void *map, void *inode);
```

**描述：** Delete a bpf_local_storage from an inode.

**返回：** 0 on success. -ENOENT if the bpf_local_storage cannot be found.

### #156 `bpf_task_storage_get`

```c
void * bpf_task_storage_get(void *map, struct task_struct *task, void *value, __u64 flags);
```

**描述：** Get a bpf_local_storage from the task. Logically, it could be thought of as getting the value from a map with task as the key.  From this perspective,  the usage is not much different from bpf_map_lookup_elem\ (map, &\ task) except this helper enf...

**返回：** A bpf_local_storage pointer is returned on success. NULL if not found or there was an error in adding a new bpf_local_storage.

### #157 `bpf_task_storage_delete`

```c
long bpf_task_storage_delete(void *map, struct task_struct *task);
```

**描述：** Delete a bpf_local_storage from a task.

**返回：** 0 on success. -ENOENT if the bpf_local_storage cannot be found.

### #210 `bpf_cgrp_storage_get`

```c
void * bpf_cgrp_storage_get(void *map, struct cgroup *cgroup, void *value, __u64 flags);
```

**描述：** Get a bpf_local_storage from the cgroup. Logically, it could be thought of as getting the value from a map with cgroup as the key.  From this perspective,  the usage is not much different from bpf_map_lookup_elem\ (map, &\ cgroup) except this help...

**返回：** A bpf_local_storage pointer is returned on success. NULL if not found or there was an error in adding a new bpf_local_storage.

### #211 `bpf_cgrp_storage_delete`

```c
long bpf_cgrp_storage_delete(void *map, struct cgroup *cgroup);
```

**描述：** Delete a bpf_local_storage from a cgroup.

**返回：** 0 on success. -ENOENT if the bpf_local_storage cannot be found.

---

## 23. 其他（8 个）

### #36 `bpf_probe_write_user`

```c
long bpf_probe_write_user(void *dst, const void *src, __u32 len);
```

**描述：** Attempt in a safe way to write len bytes from the buffer src to dst in memory. It only works for threads that are in user context, and dst must be a valid user space address. This helper should not be used to implement any kind of security mechani...

**返回：** 0 on success, or a negative error in case of failure.

### #77 `bpf_rc_repeat`

```c
long bpf_rc_repeat(void *ctx);
```

**描述：** This helper is used in programs implementing IR decoding, to report a successfully decoded repeat key message. This delays the generation of a key up event for previously generated key down event. Some IR protocols like NEC have a special IR messa...

**返回：** 0

### #78 `bpf_rc_keydown`

```c
long bpf_rc_keydown(void *ctx, __u32 protocol, __u64 scancode, __u32 toggle);
```

**描述：** This helper is used in programs implementing IR decoding, to report a successfully decoded key press with scancode, toggle value in the given protocol. The scancode will be translated to a keycode using the rc keymap, and reported as an input key ...

**返回：** 0

### #92 `bpf_rc_pointer_rel`

```c
long bpf_rc_pointer_rel(void *ctx, __s32 rel_x, __s32 rel_y);
```

**描述：** This helper is used in programs implementing IR decoding, to report a successfully decoded pointer movement. The ctx should point to the lirc sample as passed into the program. This helper is only available is the kernel was compiled with the CONF...

**返回：** 0

### #159 `bpf_bprm_opts_set`

```c
long bpf_bprm_opts_set(struct linux_binprm *bprm, __u64 flags);
```

**描述：** Set or clear certain options on bprm: BPF_F_BPRM_SECUREEXEC Set the secureexec bit which sets the AT_SECURE auxv for glibc. The bit is cleared if the flag is not specified.

**返回：** -EINVAL if invalid flags are passed, zero otherwise.

### #161 `bpf_ima_inode_hash`

```c
long bpf_ima_inode_hash(struct inode *inode, void *dst, __u32 size);
```

**描述：** 

**返回：** If the hash is larger than size, then only size bytes will be copied to dst The hash_algo is returned on success, -EOPNOTSUPP if IMA is disabled or -EINVAL if invalid arguments are passed.

### #162 `bpf_sock_from_file`

```c
struct socket * bpf_sock_from_file(struct file *file);
```

**描述：** If the given file represents a socket, returns the associated socket.

**返回：** A pointer to a struct socket on success or NULL if the file is not a socket.

### #191 `bpf_copy_from_user_task`

```c
long bpf_copy_from_user_task(void *dst, __u32 size, const void *user_ptr, struct task_struct *tsk, __u64 flags);
```

**描述：** Read size bytes from user space address user_ptr in tsk's address space, and stores the data in dst. flags is not used yet and is provided for future extensibility. This helper can only be used by sleepable programs.

**返回：** 0 on success, or a negative error in case of failure. On error dst buffer is zeroed out.

---

## 附录：按程序类型的 Helper 可用性速查

> 以下为常见程序类型可用的关键 helper 速查（非完整列表，实际可用性取决于内核版本和验证器）。

| 程序类型 | 关键可用 Helper（ID） |
|---|---|
| `XDP (xdp)` | `44`, `54`, `65`, `188`, `189`, `190`, `1`, `2`, `3`, `5`, `6`, `7`, `8`, `12`, `13`, `23`, `51`, `69`, `121`, `152`, `155` |
| `TC (sched_cls)` | `9`, `10`, `11`, `13`, `18`, `19`, `20`, `21`, `23`, `26`, `28`, `31`, `32`, `38`, `39`, `40`, `41`, `43`, `48`, `50`, `51`, `69`, `1`, `2`, `3`, `5`, `6`, `12`, `25`, `34`, `66`, `79`, `83`, `97`, `111`, `135`, `152`, `155`, `163`, `192` |
| `Socket Filter (socket)` | `1`, `2`, `3`, `5`, `6`, `12`, `14`, `15`, `16`, `25`, `46`, `47`, `79`, `80`, `107`, `108`, `130`, `131`, `132`, `133`, `134` |
| `cgroup/skb` | `1`, `2`, `3`, `5`, `6`, `12`, `14`, `15`, `16`, `25`, `46`, `47`, `79`, `80`, `107`, `108`, `130`, `131`, `132`, `133`, `134` |
| `cgroup/sock_addr` | `1`, `2`, `3`, `5`, `6`, `12`, `14`, `15`, `16`, `25`, `46`, `47`, `49`, `57`, `64`, `80`, `107`, `108`, `122`, `130`, `131`, `132`, `133`, `134` |
| `cgroup/connect4/6` | `1`, `2`, `3`, `5`, `6`, `12`, `14`, `15`, `16`, `25`, `46`, `47`, `49`, `57`, `64`, `80`, `107`, `108`, `122`, `124`, `130`, `131`, `132`, `133`, `134` |
| `sockops` | `1`, `2`, `3`, `5`, `6`, `12`, `14`, `15`, `16`, `25`, `46`, `47`, `49`, `57`, `58`, `59`, `79`, `80`, `96`, `100`, `107`, `108`, `116`, `128`, `129`, `130`, `131`, `132`, `133`, `134`, `142`, `143`, `144` |
| `sk_msg` | `1`, `2`, `3`, `5`, `6`, `12`, `25`, `46`, `47`, `49`, `53`, `57`, `60`, `61`, `62`, `63`, `70`, `71`, `107`, `108`, `130`, `131`, `132`, `133`, `134` |
| `sk_skb` | `1`, `2`, `3`, `5`, `6`, `12`, `25`, `46`, `47`, `52`, `53`, `70`, `71`, `72`, `107`, `108`, `130`, `131`, `132`, `133`, `134` |
| `sk_lookup` | `1`, `2`, `3`, `5`, `6`, `12`, `46`, `47`, `84`, `85`, `86`, `95`, `98`, `99`, `107`, `108`, `124` |
| `kprobe / fentry` | `1`, `2`, `3`, `4`, `5`, `6`, `7`, `12`, `14`, `15`, `16`, `22`, `25`, `27`, `35`, `36`, `45`, `55`, `67`, `80`, `93`, `94`, `107`, `109`, `112`, `113`, `114`, `115`, `117`, `119`, `130`, `131`, `132`, `133`, `134`, `141`, `148`, `165`, `169`, `170`, `171`, `172`, `177`, `180`, `181` |
| `tracepoint` | `1`, `2`, `3`, `4`, `5`, `6`, `7`, `12`, `14`, `15`, `16`, `22`, `25`, `27`, `35`, `45`, `55`, `67`, `80`, `93`, `94`, `107`, `109`, `112`, `113`, `114`, `115`, `119`, `130`, `131`, `132`, `133`, `134`, `141`, `148`, `165`, `169`, `170`, `171`, `172`, `177`, `180`, `181` |
| `perf_event` | `1`, `2`, `3`, `4`, `5`, `6`, `7`, `12`, `14`, `15`, `16`, `22`, `25`, `27`, `35`, `45`, `55`, `56`, `67`, `80`, `93`, `94`, `107`, `109`, `112`, `113`, `114`, `115`, `119`, `130`, `131`, `132`, `133`, `134`, `141`, `148`, `165`, `169`, `170`, `171`, `172`, `177`, `180`, `181` |
| `lwt_xmit/in/out` | `1`, `2`, `3`, `5`, `6`, `12`, `13`, `20`, `21`, `23`, `26`, `28`, `29`, `30`, `31`, `38`, `39`, `40`, `50`, `51`, `69`, `73`, `74`, `75`, `76`, `152`, `155` |
| `netfilter` | `1`, `2`, `3`, `5`, `6`, `12`, `25`, `34`, `111`, `130`, `131`, `132`, `133`, `134`, `163`, `193` |
| `LSM` | `1`, `2`, `3`, `5`, `6`, `14`, `15`, `16`, `35`, `80`, `93`, `94`, `107`, `108`, `145`, `146`, `156`, `157`, `159`, `169`, `170`, `171`, `172` |

---

## 参考链接

- man page: <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>
- libbpf 定义: `libbpf/src/bpf_helper_defs.h`（4787 行，211 个 helper）
- 内核文档: `Documentation/bpf/helpers.rst`
