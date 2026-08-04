# bpftool feature probe 输出详解

> 生成时间：2026-07-20
> 内核版本：7.0.0-27-generic (aarch64)
> bpftool 版本：v7.7.0 (libbpf v1.7)

---

## 1. 系统配置（System Configuration）

这一段检测内核编译时的 BPF 相关 CONFIG 选项和 JIT 编译器状态。

| 配置项 | 值 | 说明 |
|--------|-----|------|
| `bpf() syscall restricted to privileged users` | yes (admin can change) | BPF 系统调用仅限特权用户，管理员可修改 `/proc/sys/kernel/unprivileged_bpf_disabled` |
| `JIT compiler is enabled` | enabled | BPF JIT 编译器已启用，BPF 字节码会被编译为原生机器码以提升性能 |
| `JIT compiler hardening is disabled` | disabled | JIT 硬化关闭（硬化会混淆 JIT 输出防止逆向，但降低性能） |
| `JIT compiler kallsyms exports are enabled for root` | enabled | root 用户可在 JIT 代码中看到内核符号名 |
| `Global memory limit for JIT (unprivileged)` | ~69TB | 非特权用户的 JIT 内存上限 |

### 内核 CONFIG 选项

| CONFIG 选项 | 值 | 说明 |
|-------------|-----|------|
| `CONFIG_BPF` | y | BPF 核心支持已编译 |
| `CONFIG_BPF_SYSCALL` | y | `bpf()` 系统调用可用 |
| `CONFIG_HAVE_EBPF_JIT` | y | 架构支持 eBPF JIT（aarch64 原生支持） |
| `CONFIG_BPF_JIT` | y | BPF JIT 编译器已启用 |
| `CONFIG_BPF_JIT_ALWAYS_ON` | y | JIT 始终开启（禁用解释器，提高安全性） |
| `CONFIG_DEBUG_INFO_BTF` | y | 内核 BTF（BPF Type Format）调试信息可用，CO-RE 依赖此项 |
| `CONFIG_DEBUG_INFO_BTF_MODULES` | y | 内核模块也包含 BTF 信息 |
| `CONFIG_CGROUPS` | y | cgroup 支持 |
| `CONFIG_CGROUP_BPF` | y | cgroup BPF 程序支持 |
| `CONFIG_BPF_EVENTS` | y | BPF 事件（tracepoint/kprobe/uprobe）支持 |
| `CONFIG_KPROBE_EVENTS` | y | kprobe 事件支持 |
| `CONFIG_UPROBE_EVENTS` | y | uprobe 事件支持 |
| `CONFIG_TRACING` | y | tracing 基础设施 |
| `CONFIG_FTRACE_SYSCALLS` | y | ftrace 系统调用追踪 |
| `CONFIG_FUNCTION_ERROR_INJECTION` | y | 函数错误注入 |
| `CONFIG_BPF_KPROBE_OVERRIDE` | y | BPF kprobe 覆盖（bpf_override_return），用于安全示例 |
| `CONFIG_NET` | y | 网络支持 |
| `CONFIG_XDP_SOCKETS` | y | XDP socket（AF_XDP）支持 |
| `CONFIG_LWTUNNEL_BPF` | y | 轻量隧道 BPF（lwt_in/lwt_out/lwt_xmit） |
| `CONFIG_NET_ACT_BPF` | m | tc action BPF（模块形式） |
| `CONFIG_NET_CLS_BPF` | m | tc classifier BPF（模块形式） |
| `CONFIG_NET_CLS_ACT` | y | tc 分类器/动作支持 |
| `CONFIG_NET_SCH_INGRESS` | m | ingress qdisc（模块形式） |
| `CONFIG_XFRM` | y | IPsec 框架 |
| `CONFIG_IPV6_SEG6_BPF` | y | IPv6 Segment Routing BPF |
| `CONFIG_BPF_LIRC_MODE2` | not set | LIRC（红外遥控）BPF 不可用 |
| `CONFIG_BPF_STREAM_PARSER` | y | BPF 流解析器（sockmap/sk_msg） |
| `CONFIG_NETFILTER_XT_MATCH_BPF` | m | Netfilter BPF 匹配（模块形式） |
| `CONFIG_TEST_BPF` | m | BPF 自测模块 |
| `CONFIG_HZ` | 1000 | 内核时钟频率 1000Hz |

### 系统调用可用性

```
bpf() syscall is available
```
`bpf()` 系统调用可用，用户态可通过 `syscall(__NR_bpf, cmd, attr, size)` 与内核 BPF 子系统交互。

---

## 2. eBPF 程序类型（Program Types）

本内核支持 **32 种** BPF 程序类型（1 种不可用）：

| 程序类型 | 状态 | 说明 | 典型用途 |
|----------|------|------|---------|
| `socket_filter` | ✅ | socket 过滤器 | 抓包（如 lesson 23-http） |
| `kprobe` | ✅ | 内核函数探针（入口/返回） | 追踪内核函数（如 lesson 2/33） |
| `sched_cls` | ✅ | tc 分类器 | 流量控制（如 lesson 20-tc/50-tcx） |
| `sched_act` | ✅ | tc 动作 | tc 动作执行 |
| `tracepoint` | ✅ | 内核 tracepoint | 追踪系统调用/调度事件（如 lesson 4/6/7/8） |
| `xdp` | ✅ | XDP 程序 | 高性能包处理（如 lesson 21/41/42） |
| `perf_event` | ✅ | perf 事件程序 | CPU 采样 profiling（如 lesson 12-profile） |
| `cgroup_skb` | ✅ | cgroup 网络包过滤 | cgroup 级流量统计/控制（如 lesson cgroup） |
| `cgroup_sock` | ✅ | cgroup socket 事件 | socket 创建/释放 |
| `lwt_in` / `lwt_out` / `lwt_xmit` | ✅ | 轻量隧道 | 网络隧道封装 |
| `sock_ops` | ✅ | socket 操作 | TCP 连接加速（如 lesson 29-sockops） |
| `sk_skb` | ✅ | socket 缓冲区 | sockmap 数据流处理 |
| `cgroup_device` | ✅ | cgroup 设备控制 | 设备访问控制 |
| `sk_msg` | ✅ | socket 消息 | sk_msg 重定向（如 lesson 29） |
| `raw_tracepoint` | ✅ | 原始 tracepoint | 轻量追踪（无 tracepoint 参数解析） |
| `cgroup_sock_addr` | ✅ | cgroup 地址绑定 | bind/connect 权限控制 |
| `lwt_seg6local` | ✅ | IPv6 Segment Routing | SRv6 程序 |
| `lirc_mode2` | ❌ | LIRC 模式 2 | 红外遥控（本机不可用） |
| `sk_reuseport` | ✅ | socket reuseport | 负载均衡到多个 socket |
| `flow_dissector` | ✅ | 流分类器 | 解析网络包元数据 |
| `cgroup_sysctl` | ✅ | cgroup sysctl | 拦截/修改 sysctl |
| `raw_tracepoint_writable` | ✅ | 可写原始 tracepoint | 修改 tracepoint 参数 |
| `cgroup_sockopt` | ✅ | cgroup sockopt | getsockopt/setsockopt 拦截 |
| `tracing` | ✅ | tracing 程序 | fentry/fexit/mod_ret（如 lesson 3/34） |
| `struct_ops` | ✅ | struct_ops | 扩展内核子系统（如 TCP 拥塞控制） |
| `ext` | ✅ | 程序扩展 | 替换/扩展已加载的 BPF 程序 |
| `lsm` | ✅ | BPF LSM | 安全策略（如 lesson 19-lsm-connect） |
| `sk_lookup` | ✅ | socket 查找 | 主动 socket 查找（替代 bind） |
| `syscall` | ✅ | BPF 系统调用程序 | 可从用户态直接调用的 BPF 程序 |
| `netfilter` | ✅ | Netfilter BPF | nftables 集成 |

---

## 3. eBPF Map 类型（Map Types）

本内核支持 **34 种** BPF map 类型：

| Map 类型 | 状态 | 说明 | 典型用途 |
|----------|------|------|---------|
| `hash` | ✅ | 哈希表 | 通用 kv 存储（最常用） |
| `array` | ✅ | 数组 | 索引式存储（配置、统计） |
| `prog_array` | ✅ | 程序数组 | 尾调用（bpf_tail_call） |
| `perf_event_array` | ✅ | perf 事件数组 | perf buffer 事件传输（如 lesson 7） |
| `percpu_hash` | ✅ | 每 CPU 哈希表 | 无锁 per-cpu 统计 |
| `percpu_array` | ✅ | 每 CPU 数组 | 高性能计数器（如 lesson 9/10） |
| `stack_trace` | ✅ | 栈追踪表 | 存储调用栈（bpf_get_stackid） |
| `cgroup_array` | ✅ | cgroup 数组 | cgroup 引用 |
| `lru_hash` | ✅ | LRU 哈希表 | 自动淘汰的哈希表 |
| `lru_percpu_hash` | ✅ | 每 CPU LRU 哈希 | 高性能 LRU |
| `lpm_trie` | ✅ | 最长前缀匹配 | 路由表查找 |
| `array_of_maps` | ✅ | 数组 of map | 嵌套 map（map-in-map） |
| `hash_of_maps` | ✅ | 哈希 of map | 嵌套 map |
| `devmap` | ✅ | 设备表 | XDP 重定向到网卡 |
| `sockmap` | ✅ | socket 表 | sockmap/sk_msg 重定向 |
| `cpumap` | ✅ | CPU 表 | XDP 重定向到 CPU |
| `xskmap` | ✅ | XSK 表 | AF_XDP socket 映射 |
| `sockhash` | ✅ | socket 哈希 | 按五元组查找 socket（如 lesson 29） |
| `cgroup_storage` | ✅ | cgroup 存储 | cgroup 级本地存储 |
| `reuseport_sockarray` | ✅ | reuseport socket 数组 | socket 负载均衡 |
| `percpu_cgroup_storage` | ✅ | 每 CPU cgroup 存储 | 高性能 cgroup 统计 |
| `queue` | ✅ | 队列 | FIFO 数据结构 |
| `stack` | ✅ | 栈 | LIFO 数据结构 |
| `sk_storage` | ✅ | socket 本地存储 | per-socket 数据 |
| `devmap_hash` | ✅ | 设备哈希表 | 按索引哈希查找设备 |
| `struct_ops` | ✅ | struct_ops | 注册内核子系统实现 |
| `ringbuf` | ✅ | 环形缓冲区 | 内核→用户态事件传输（最常用，如 lesson 8/11） |
| `inode_storage` | ✅ | inode 存储 | per-file 数据 |
| `task_storage` | ✅ | 任务存储 | per-process 数据 |
| `bloom_filter` | ✅ | 布隆过滤器 | 快速集合存在性判断 |
| `user_ringbuf` | ✅ | 用户态环形缓冲区 | 用户态→内核态消息（如 lesson 35） |
| `cgrp_storage` | ✅ | cgroup 存储 | per-cgroup 数据 |
| `arena` | ✅ | arena | 零拷贝共享内存（如 features/bpf_arena） |
| `insn_array` | ✅ | 指令数组 | 存储 BPF 指令 |

---

## 4. eBPF 辅助函数（Helper Functions）

bpftool 按程序类型分组列出了每种程序类型可用的 helper 函数，共 **2429 条**记录（不同程序类型可能共享同一个 helper）。

### 常用 helper 分类

#### 通用 map 操作
| Helper | 说明 |
|--------|------|
| `bpf_map_lookup_elem` | 查询 map 元素 |
| `bpf_map_update_elem` | 更新 map 元素 |
| `bpf_map_delete_elem` | 删除 map 元素 |
| `bpf_map_push_elem` | 队列 push |
| `bpf_map_pop_elem` | 队列 pop |
| `bpf_map_peek_elem` | 查看 queue/stack 头部 |

#### 进程/线程信息
| Helper | 说明 |
|--------|------|
| `bpf_get_current_pid_tgid` | 获取当前 PID 和 TID |
| `bpf_get_current_uid_gid` | 获取 UID 和 GID |
| `bpf_get_current_comm` | 获取当前进程名 |
| `bpf_get_current_task` | 获取 task_struct 指针 |
| `bpf_get_current_cgroup_id` | 获取当前 cgroup ID |

#### 时间/随机
| Helper | 说明 |
|--------|------|
| `bpf_ktime_get_ns` | 获取内核时间（纳秒） |
| `bpf_get_prandom_u32` | 获取随机数 |

#### Ring buffer / perf 事件
| Helper | 说明 |
|--------|------|
| `bpf_ringbuf_reserve` | 预留 ringbuf 空间 |
| `bpf_ringbuf_submit` | 提交 ringbuf 数据 |
| `bpf_ringbuf_discard` | 丢弃 ringbuf 数据 |
| `bpf_perf_event_output` | 输出到 perf event array |
| `bpf_user_ringbuf_drain` | 排空 user ringbuf |

#### 内存读写
| Helper | 说明 |
|--------|------|
| `bpf_probe_read` | 读取内核/用户内存（已废弃，用下面两个替代） |
| `bpf_probe_read_kernel` | 读取内核内存 |
| `bpf_probe_read_user` | 读取用户态内存 |
| `bpf_probe_read_kernel_str` | 读取内核字符串 |
| `bpf_probe_read_user_str` | 读取用户态字符串 |
| `bpf_probe_write_user` | 写入用户态内存（危险，需特权） |

#### 栈追踪
| Helper | 说明 |
|--------|------|
| `bpf_get_stackid` | 获取栈 ID（存入 stack_trace map） |
| `bpf_get_stack` | 获取完整栈到缓冲区 |

#### 网络/包处理
| Helper | 说明 |
|--------|------|
| `bpf_skb_load_bytes` | 读取 skb 中的数据 |
| `bpf_redirect` | 重定向包到其他网卡 |
| `bpf_redirect_peer` | 重定向到对端网卡（如 lesson 42） |
| `bpf_xdp_adjust_head` | 调整 XDP 包头 |
| `bpf_xdp_adjust_tail` | 调整 XDP 包尾 |
| `bpf_csum_diff` | 计算校验和差值（如 lesson 42） |

#### 信号/覆盖
| Helper | 说明 |
|--------|------|
| `bpf_send_signal` | 向当前进程发送信号（如 lesson 25） |
| `bpf_override_return` | 覆盖 kprobe 返回值（如 lesson 34） |

#### Dynptr
| Helper | 说明 |
|--------|------|
| `bpf_dynptr_from_mem` | 从内存创建 dynptr |
| `bpf_dynptr_read` | 从 dynptr 读取 |
| `bpf_dynptr_write` | 写入 dynptr |
| `bpf_dynptr_data` | 获取 dynptr 数据指针 |

---

## 5. eBPF ISA 扩展（Misc Features）

| 特性 | 状态 | 说明 |
|------|------|------|
| `Large program size limit` | ✅ | 支持大程序（指令数上限提升） |
| `Bounded loop` | ✅ | 支持有界循环（for/while with upper bound） |
| `ISA extension v2` | ✅ | BPF 指令集 v2（64 位寄存器、原子操作等） |
| `ISA extension v3` | ✅ | BPF 指令集 v3（有符号比较跳转、32 位操作等） |
| `ISA extension v4` | ✅ | BPF 指令集 v4（signed 64 位乘除、arena 指针转换等） |

---

## 6. 完整查看命令

```bash
# 完整输出
bpftool feature probe

# JSON 格式
bpftool feature probe -j

# 只看内核 CONFIG
bpftool feature probe | grep CONFIG

# 只看程序类型
bpftool feature probe | grep program_type

# 只看 map 类型
bpftool feature probe | grep map_type

# 查看某个程序类型的可用 helper
bpftool feature probe | awk '/program type kprobe/,/^$/' | head -30

# 查看内核 BTF 中的 iter 类型
bpftool btf dump file /sys/kernel/btf/vmlinux | grep "STRUCT 'bpf_iter__"
```

---

## 7. 本仓库示例与特性的映射

| 示例 | 使用的程序类型 | 使用的 map 类型 | 关键 helper |
|------|--------------|----------------|-------------|
| 1-helloworld | tracepoint | — | bpf_trace_printk |
| 2-kprobe-unlink | kprobe | ringbuf | bpf_get_current_pid_tgid, bpf_probe_read_kernel_str |
| 3-fentry-unlink | tracing (fentry) | ringbuf | BPF_CORE_READ |
| 4-opensnoop | tracepoint | hash + ringbuf | bpf_probe_read_user_str |
| 5-uprobe-bashreadline | kprobe (uprobe) | ringbuf | bpf_probe_read_user_str |
| 6-sigsnoop | tracepoint | hash + ringbuf | bpf_map_update_elem |
| 7-execsnoop | tracepoint | perf_event_array | bpf_perf_event_output |
| 8-exitsnoop | tracepoint | hash + ringbuf | BPF_CORE_READ |
| 9-runqlat | tracepoint | hash + array | __sync_fetch_and_add |
| 10-hardirqs | tracepoint | hash | bpf_get_smp_processor_id |
| 11-bootstrap | tracepoint | hash + ringbuf | BPF_CORE_READ |
| 12-profile | perf_event | ringbuf | bpf_get_stack, bpf_program__attach_perf_event |
| 20-tc | sched_cls | — | bpf_skb_load_bytes |
| 21-xdp | xdp | — | bpf_printk |
| 23-http | socket_filter | ringbuf | bpf_skb_load_bytes |
| 29-sockops | sock_ops + sk_msg | sockhash | bpf_sock_hash_update, bpf_msg_redirect_hash |
| 30-sslsniff | kprobe (uprobe) | hash + ringbuf | bpf_probe_read_user |
| 33-funclatency | kprobe + kretprobe | hash + array | bpf_program__attach_kprobe_opts |
| 35-user-ringbuf | perf_event | user_ringbuf | bpf_user_ringbuf_drain, bpf_dynptr_read |
| 42-xdp-loadbalancer | xdp | array | bpf_redirect_peer, bpf_csum_diff |
| 43-kfuncs | tracepoint | ringbuf | bpf_kfunc_greet (自定义 kfunc) |
| 49-hid | kprobe | ringbuf | bpf_get_current_pid_tgid |
| cgroup | cgroup_skb | percpu_array | bpf_map_lookup_elem |
| features/bpf_arena | tracepoint | arena + ringbuf | bpf_arena_alloc_pages |
| features/bpf_iters | tracing (iter) | — | BPF_SEQ_PRINTF |
| features/struct_ops | struct_ops | struct_ops | — |
| features/dynptr | tracepoint | ringbuf | bpf_dynptr_from_mem, bpf_dynptr_read, bpf_dynptr_write |
