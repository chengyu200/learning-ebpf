# eBPF Map 类型使用频率排名

> 数据来源：内核源码 `include/uapi/linux/bpf.h` + 本仓库 `src/` 实际使用统计 + eBPF 生态实践（Cilium、bcc、Parca 等）

## 排名总表

| 排名 | Map 类型 | 本仓库使用数 | 典型用途 | 高频原因 |
|------|---------|:------------:|---------|---------|
| 1 | `BPF_MAP_TYPE_RINGBUF` | 40 个示例 | 内核→用户态事件传递（trace、审计、监控） | 现代标准：环形缓冲区，无锁、多 producer 单 consumer、内置 reserve/submit、替代了旧的 perf_event_array。几乎所有需要上报事件的程序都用它 |
| 2 | `BPF_MAP_TYPE_HASH` | 28 个示例 | 键值存储：PID→进程信息、连接跟踪、配置白名单 | 最通用的存储原语：O(1) 查找/插入/删除，支持任意 key/value 结构体。几乎所有需要"按 key 维护状态"的场景首选 |
| 3 | `BPF_MAP_TYPE_PERCPU_ARRAY` | 13 个示例 | per-CPU 计数器（包数、字节数、延迟统计） | 避免原子操作和锁竞争：每个 CPU 独立计数，用户态聚合。网络程序（TC/XDP/cgroup）统计流量的标准方式 |
| 4 | `BPF_MAP_TYPE_ARRAY` | 10 个示例 | 配置表（全局参数）、查找表（端口映射）、全局单例 | 简单高效：固定大小、索引访问、无需 hash 计算。适合"少量配置项"或"按 index 查找"场景 |
| 5 | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | 4 个示例 | 旧版事件传递（perf 子系统） | ringbuf 出现前的标准事件传递方式。旧代码（bcc 工具）仍大量使用，但新代码已转向 ringbuf |
| 6 | `BPF_MAP_TYPE_LRU_HASH` | 本仓库未用 | 生产环境连接跟踪、大容量缓存 | Cilium 等生产项目大量使用：自动 LRU 淘汰防止 map 无限增长。本仓库是学习项目（短生命周期），不需要 LRU |
| 7 | `BPF_MAP_TYPE_SOCKMAP` | 5 个示例 | sockmap 代理、sk_skb 流解析、socket 重定向 | socket 级零拷贝代理的基础设施。`bpf_program__attach_sockmap` 的目标 |
| 8 | `BPF_MAP_TYPE_SOCKHASH` | 5 个示例 | 同 sockmap 但用 hash key | 支持复合 key（sip+dip+sport+dport），比 sockmap 的整数 key 更灵活。29-sockops 和 53-transparent-proxy 使用 |
| 9 | `BPF_MAP_TYPE_STACK_TRACE` | 1 个示例 | 性能分析：调用栈采集 | profiling/内存泄漏分析专用。按 stack id 去重存储调用栈 |
| 10 | `BPF_MAP_TYPE_DEVMAP` | 1 个示例 | XDP 网卡重定向 | XDP 生态专用：将包从一个网卡重定向到另一个 |
| 11 | `BPF_MAP_TYPE_CPUMAP` | 1 个示例 | XDP 跨 CPU 重定向 | XDP 生态专用：将包从接收 CPU 重定向到目标 CPU 的 backlog |
| 12 | `BPF_MAP_TYPE_STRUCT_OPS` | 1 个示例 | 内核函数指针表覆盖（TCP 拥塞控制） | 66-struct-ops-tcp-cc 使用，通过 `SEC(".struct_ops")` 自动创建 |
| 13 | `BPF_MAP_TYPE_LPM_TRIE` | 本仓库未用 | 路由表、IP 前缀匹配 | 网络路由专用：最长前缀匹配。Cilium 的路由表使用 |
| 14 | `BPF_MAP_TYPE_PERCPU_HASH` | 本仓库未用 | per-CPU 键值计数器 | 结合了 per-CPU 和 hash 的优势，但使用场景较窄（既需要 key 查找又需要 per-CPU 计数） |

## 频率分布的底层原因

### 前 4 名覆盖 90%+ 的使用场景

**1. RINGBUF** — 几乎所有 BPF 程序都需要向用户态报告结果（事件、统计、审计），ringbuf 是最现代、最高效的方式

**2. HASH** — 任何需要"按 key 维护状态"的场景（PID→info、连接跟踪、白名单），hash 是最自然的数据结构

**3. PERCPU_ARRAY** — 统计计数是 BPF 最常见的用途之一，per-CPU 避免了原子操作和 cache line 争用

**4. ARRAY** — 配置传递和简单查找表，比 hash 更轻量（无 hash 计算、无冲突）

### 第 5-8 名：领域专用 map

- `PERF_EVENT_ARRAY` — 旧版事件传递（正在被 ringbuf 替代）
- `LRU_HASH` — 生产环境的连接跟踪（自动淘汰防溢出）
- `SOCKMAP/SOCKHASH` — socket 代理和重定向

### 第 9 名以后：高度专用

- `STACK_TRACE` — profiling 专用
- `DEVMAP/CPUMAP` — XDP 基础设施
- `STRUCT_OPS` — 内核函数表覆盖
- `LPM_TRIE` — 路由表

## 本仓库详细使用统计

### 按实际声明数排序（`__uint(type, BPF_MAP_TYPE_*)`）

| Map 类型 | 声明数 | 使用目录数 |
|----------|:------:|:---------:|
| `BPF_MAP_TYPE_RINGBUF` | 41 | 40 |
| `BPF_MAP_TYPE_HASH` | 36 | 28 |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | 17 | 13 |
| `BPF_MAP_TYPE_ARRAY` | 13 | 10 |
| `BPF_MAP_TYPE_SOCKMAP` | 5 | 5 |
| `BPF_MAP_TYPE_SOCKHASH` | 5 | 5 |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | 4 | 4 |
| `BPF_MAP_TYPE_USER_RINGBUF` | 1 | 1 |
| `BPF_MAP_TYPE_STACK_TRACE` | 1 | 1 |
| `BPF_MAP_TYPE_DEVMAP` | 2 | 1 |
| `BPF_MAP_TYPE_STRUCT_OPS` | 0 (auto) | 1 |
| `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` | 1 | 1 |
| `BPF_MAP_TYPE_CPUMAP` | 1 | 1 |
| `BPF_MAP_TYPE_ARENA` | 1 | 1 |

### 各 Map 类型使用的示例目录

#### 1. RINGBUF（40 个目录）
```
2-kprobe-unlink, 3-fentry-unlink, 4-opensnoop, 5-uprobe-bashreadline,
6-sigsnoop, 8-exitsnoop, 11-bootstrap, 12-profile, 23-http, 30-sslsniff,
31-goroutine, 35-user-ringbuf, 37-uprobe-rust, 38-btf-uprobe, 39-nginx,
40-mysql, 41-xdp-tcpdump, 43-kfuncs, 49-hid, 51-cgroup-sysctl,
54-httpstat, 58-iter-open-coded, 63-tp-btf, 64-fsession, 66-struct-ops-tcp-cc,
69-freplace, 70-fexit-unlink, 72-ksyscall, 74-uprobe-multi-session,
75-kprobe-multi, 75-netfilter, 76-cgroup-device, 77-sock-addr-monitor,
79-cgroup-sock, 80-cgroup-sockopt, 81-sk-reuseport, 81-sk-skb,
82-cgroup-skb, 83-flow-dissector, features (bpf_arena, dynptr)
```

#### 2. HASH（28 个目录）
```
9-runqlat, 10-hardirqs, 11-bootstrap, 13-tcpconnlat, 14-tcpstates,
14b-tcprtt, 15-javagc, 16-memleak, 17-biopattern, 24-hide, 26-sudo,
27-replace, 30-sslsniff, 33-funclatency, 39-nginx, 4-opensnoop,
52-sk-lookup-proxy-v2, 53-transparent-proxy, 53-transparent-proxy-v2,
53-transparent-proxy-v3, 53-transparent-proxy-v4, 64-fsession,
67-syscall-prog, 6-sigsnoop, 72-ksyscall, 74-uprobe-multi-session,
76-cgroup-device, 8-exitsnoop
```

#### 3. PERCPU_ARRAY（13 个目录）
```
46-xdp-test, 50-tcx, 53-transparent-proxy-v4, 55-xdp-devmap,
56-xdp-cpumap, 65-tp-vs-raw-tp, 67-syscall-prog, 71-netkit,
75-netfilter, 76-tc-tcx, 78-tcx-chain, 83-flow-dissector, cgroup
```

#### 4. ARRAY（10 个目录）
```
9-runqlat, 28-detach, 42-xdp-loadbalancer, 53-transparent-proxy,
53-transparent-proxy-v2, 53-transparent-proxy-v3, 53-transparent-proxy-v4,
55-xdp-devmap, 82-cgroup-skb, features (bpf_wq)
```

#### 5. SOCKMAP（5 个目录）
```
52-sk-lookup-proxy, 52-sk-lookup-proxy-v2, 53-transparent-proxy-v3,
53-transparent-proxy-v4, 81-sk-skb
```

#### 6. SOCKHASH（5 个目录）
```
29-sockops, 53-transparent-proxy, 53-transparent-proxy-v2,
53-transparent-proxy-v3, 53-transparent-proxy-v4
```

#### 7. PERF_EVENT_ARRAY（4 个目录）
```
7-execsnoop, 13-tcpconnlat, 14-tcpstates, 15-javagc
```

## 内核支持的全部 Map 类型（36 种）

来源：`include/uapi/linux/bpf.h` `enum bpf_map_type`

| # | Map 类型 | 说明 |
|---|---------|------|
| 0 | `BPF_MAP_TYPE_UNSPEC` | 未指定 |
| 1 | `BPF_MAP_TYPE_HASH` | 哈希表 |
| 2 | `BPF_MAP_TYPE_ARRAY` | 数组 |
| 3 | `BPF_MAP_TYPE_PROG_ARRAY` | 程序数组（尾调用） |
| 4 | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | perf 事件数组 |
| 5 | `BPF_MAP_TYPE_PERCPU_HASH` | per-CPU 哈希表 |
| 6 | `BPF_MAP_TYPE_PERCPU_ARRAY` | per-CPU 数组 |
| 7 | `BPF_MAP_TYPE_STACK_TRACE` | 调用栈存储 |
| 8 | `BPF_MAP_TYPE_CGROUP_ARRAY` | cgroup 数组（已废弃） |
| 9 | `BPF_MAP_TYPE_LRU_HASH` | LRU 哈希表 |
| 10 | `BPF_MAP_TYPE_LRU_PERCPU_HASH` | LRU per-CPU 哈希表 |
| 11 | `BPF_MAP_TYPE_LPM_TRIE` | 最长前缀匹配 |
| 12 | `BPF_MAP_TYPE_ARRAY_OF_MAPS` | map-in-map（数组） |
| 13 | `BPF_MAP_TYPE_HASH_OF_MAPS` | map-in-map（哈希） |
| 14 | `BPF_MAP_TYPE_DEVMAP` | 网卡映射 |
| 15 | `BPF_MAP_TYPE_SOCKMAP` | socket 映射 |
| 16 | `BPF_MAP_TYPE_CPUMAP` | CPU 映射 |
| 17 | `BPF_MAP_TYPE_XSKMAP` | XSK socket 映射 |
| 18 | `BPF_MAP_TYPE_SOCKHASH` | socket 哈希映射 |
| 19 | `BPF_MAP_TYPE_CGROUP_STORAGE` | cgroup 存储（已废弃） |
| 20 | `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` | reuseport socket 数组 |
| 21 | `BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE` | per-CPU cgroup 存储（已废弃） |
| 22 | `BPF_MAP_TYPE_QUEUE` | 队列（FIFO） |
| 23 | `BPF_MAP_TYPE_STACK` | 栈（LIFO） |
| 24 | `BPF_MAP_TYPE_SK_STORAGE` | socket 本地存储 |
| 25 | `BPF_MAP_TYPE_DEVMAP_HASH` | 网卡哈希映射 |
| 26 | `BPF_MAP_TYPE_STRUCT_OPS` | 结构体操作表 |
| 27 | `BPF_MAP_TYPE_RINGBUF` | 环形缓冲区 |
| 28 | `BPF_MAP_TYPE_INODE_STORAGE` | inode 本地存储 |
| 29 | `BPF_MAP_TYPE_TASK_STORAGE` | 任务本地存储 |
| 30 | `BPF_MAP_TYPE_BLOOM_FILTER` | 布隆过滤器 |
| 31 | `BPF_MAP_TYPE_USER_RINGBUF` | 用户→内核环形缓冲区 |
| 32 | `BPF_MAP_TYPE_CGRP_STORAGE` | cgroup 本地存储 |
| 33 | `BPF_MAP_TYPE_ARENA` | arena 内存区域 |
| 34 | `BPF_MAP_TYPE_INSN_ARRAY` | 指令数组 |
| 35 | `BPF_MAP_TYPE_RHASH` | 可重试哈希表 |

## 未在排名中但值得关注的 Map 类型

| Map 类型 | 说明 | 使用场景 |
|----------|------|---------|
| `BPF_MAP_TYPE_PROG_ARRAY` | 尾调用程序数组 | `bpf_tail_call` 的目标 map，实现程序间跳转 |
| `BPF_MAP_TYPE_LRU_PERCPU_HASH` | LRU per-CPU 哈希 | 结合 LRU 淘汰和 per-CPU 性能，Cilium 连接跟踪使用 |
| `BPF_MAP_TYPE_SK_STORAGE` | socket 本地存储 | 按 socket 存储自定义数据，无需全局 map 查找 |
| `BPF_MAP_TYPE_TASK_STORAGE` | 任务本地存储 | 按 task_struct 存储自定义数据 |
| `BPF_MAP_TYPE_BLOOM_FILTER` | 布隆过滤器 | 快速判断元素"可能在集合中"或"绝对不在" |
| `BPF_MAP_TYPE_QUEUE` / `STACK` | 队列/栈 | FIFO/LIFO 数据结构，用于 BPF 程序间通信 |
| `BPF_MAP_TYPE_ARENA` | arena 内存 | 大块共享内存，BPF 程序可直接 mmap |
