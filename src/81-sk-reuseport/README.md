# 81-sk-reuseport

用 `BPF_PROG_TYPE_SK_REUSEPORT` 自定义 SO_REUSEPORT 的连接分配策略，演示 `sk_reuseport`（仅选择）和 `sk_reuseport/migrate`（选择 + 迁移）两种模式。

## 什么是 BPF SK_REUSEPORT

`SO_REUSEPORT` 允许多个 socket 绑定同一端口，内核默认按 4-tuple hash 分配连接。`BPF_PROG_TYPE_SK_REUSEPORT` 允许 BPF 程序**自定义连接分配策略**——例如按源 IP、端口、协议等选择 listener，而非默认的 hash。

### 上下文：`struct sk_reuseport_md`

```c
struct sk_reuseport_md {
    void *data;              // TCP/UDP 头起始
    void *data_end;          // 可访问数据末尾
    __u32 len;               // 包总长度
    __u32 eth_protocol;      // ETH_P_IP / ETH_P_IPV6
    __u32 ip_protocol;       // IPPROTO_TCP / IPPROTO_UDP
    __u32 bind_inany;        // 绑定到 INANY 地址？
    __u32 hash;              // 包 4-tuple 的 hash
    struct bpf_sock *sk;     // 当前 socket（reuseport 组中的一个）
    struct bpf_sock *migrating_sk;  // 迁移中的 socket（NULL=选择，非NULL=迁移）
};
```

### 两个挂载点

| SEC | attach_type | 触发时机 | 迁移支持 |
|-----|------------|---------|---------|
| `sk_reuseport` | `BPF_SK_REUSEPORT_SELECT` | 新连接到来 | ❌ |
| `sk_reuseport/migrate` | `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` | 新连接 + socket 关闭迁移 | ✅ |

**`migrating_sk` 字段**：
- `NULL` → 选择模式：新连接到来，选择一个 listener
- 非 `NULL` → 迁移模式：原 listener 关闭，将其未完成的连接迁移到其他 listener

### 返回值

| 返回值 | 含义 | 说明 |
|--------|------|------|
| `SK_PASS` (1) | 放行 | 使用 `bpf_sk_select_reuseport()` 选择的 socket；如果未选择，内核回退到 hash |
| `SK_DROP` (0) | 拒绝 | 连接被拒绝（ECONNREFUSED） |

**重要**：BPF 程序的返回值**不是 socket 索引**！它是 `SK_PASS`/`SK_DROP` 判决值。要选择 socket，必须调用 `bpf_sk_select_reuseport()` helper，从 `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` map 中选择。

内核源码 `net/core/filter.c` 的 `bpf_run_sk_reuseport` 函数：
```c
action = bpf_prog_run(prog, &reuse_kern);    // BPF 返回值
if (action == SK_PASS)                        // 返回 1
    return reuse_kern.selected_sk;            // bpf_sk_select_reuseport 设置的 socket
else                                          // 返回 0
    return ERR_PTR(-ECONNREFUSED);            // 直接拒绝连接！
```

### attach 方式（非 bpf_link）

sk_reuseport 程序通过 `setsockopt` attach，而非 `bpf_link_create`：

```c
int prog_fd = bpf_program__fd(prog);
setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd));
```

只需 attach 到 reuseport 组中的**一个** socket，对整个组生效。

## 做什么

**阶段 1：`sk_reuseport`（仅选择）**
1. 创建 3 个 TCP listener（SO_REUSEPORT 绑定同一端口）
2. attach `SEC("sk_reuseport")` 程序（基于 hash 选择 socket）
3. fork 子进程连接 6 次
4. 父进程 accept 并记录哪个 listener 收到连接
5. 打印 BPF select 事件

**阶段 2：`sk_reuseport/migrate`（选择 + 迁移）**
6. 替换为 `SEC("sk_reuseport/migrate")` 程序（同一 reuseport 组，直接替换 BPF 程序）
7. fork 子进程再连接 3 次
8. 展示 migrate 程序处理选择事件
9. 打印 BPF 事件（migrate 程序同时处理 select 和 migrate）

## 运行

```bash
make -C src/81-sk-reuseport
sudo ./src/81-sk-reuseport/sk-reuseport
```

### 输出示例

```
Created 3 TCP listeners with SO_REUSEPORT on port 48421

══ Phase 1: SEC("sk_reuseport") — select only ══

Attached select_prog to reuseport group
Making 6 connections...

  listener[0] accepted 3 connections
  listener[1] accepted 2 connections
  listener[2] accepted 1 connections

BPF events:
  [BPF] SELECT  socket[1]  hash=2474209177  proto=6  pid=136770
  [BPF] SELECT  socket[1]  hash=395679427  proto=6  pid=136770
  [BPF] SELECT  socket[2]  hash=1884535427  proto=6  pid=136770
  [BPF] SELECT  socket[0]  hash=3426017187  proto=6  pid=136770
  [BPF] SELECT  socket[0]  hash=258299301  proto=6  pid=136770
  [BPF] SELECT  socket[0]  hash=3452381934  proto=6  pid=136770

══ Phase 2: SEC("sk_reuseport/migrate") — select + migrate ══

Replaced with migrate_prog (handles select + migrate)
Making 3 more connections (same 3 listeners)...

  listener[0] accepted 0 connections
  listener[1] accepted 2 connections
  listener[2] accepted 1 connections

BPF events:
  [BPF] SELECT  socket[1]  hash=3256910446  proto=6  pid=136772
  [BPF] SELECT  socket[1]  hash=2221944796  proto=6  pid=136772
  [BPF] SELECT  socket[2]  hash=2293301207  proto=6  pid=136772

Done.
```

> 注：`migrating_sk` 字段在正常连接时为 NULL（SELECT 模式），仅在 reuseport 组中的 socket 被关闭且有待处理连接时才非 NULL（MIGRATE 模式）。

## 教学概念

| 概念 | 说明 |
|------|------|
| `SEC("sk_reuseport")` | 仅选择模式（新连接） |
| `SEC("sk_reuseport/migrate")` | 选择 + 迁移模式 |
| `sk_reuseport_md` 上下文 | `hash`/`migrating_sk`/`ip_protocol`/`data`/`data_end` |
| `migrating_sk` | NULL=选择模式，非NULL=迁移模式 |
| 返回值 | `SK_PASS`(1)=放行, `SK_DROP`(0)=拒绝（ECONNREFUSED） |
| `bpf_sk_select_reuseport()` | 从 REUSEPORT_SOCKARRAY map 选择 socket（设置 `selected_sk`） |
| `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` | 存储 socket fd 的 map，key=索引 → value=fd |
| `SO_ATTACH_REUSEPORT_EBPF` | 通过 setsockopt attach（非 bpf_link） |
| `SO_REUSEPORT` | 允许多个 socket 绑定同一端口 |

## 技术细节

### SO_REUSEPORT 工作原理

没有 BPF 时，内核按 4-tuple hash 将连接分配到 reuseport 组中的 socket：

```
connect(127.0.0.1:port) → kernel hash(4-tuple) % num_socks → socket[idx]
```

有 BPF 时，BPF 程序通过 `bpf_sk_select_reuseport()` 选择 socket：

```c
SEC("sk_reuseport")
int select_prog(struct sk_reuseport_md *ctx) {
    __u32 key = ctx->hash % NUM_SOCKETS;
    bpf_sk_select_reuseport(ctx, &reuseport_array, &key, 0);
    return SK_PASS;  /* 放行，使用 selected_sk */
}
```

**关键**：返回值不是 socket 索引，而是 `SK_PASS`(1)/`SK_DROP`(0)。选择 socket 通过 `bpf_sk_select_reuseport()` helper 完成。

### 选择 vs 迁移

**选择**（`migrating_sk == NULL`）：
- 新连接到来（如 TCP SYN）
- BPF 程序选择一个 listener 接收
- 返回 socket 索引

**迁移**（`migrating_sk != NULL`）：
- reuseport 组中的某个 socket 被关闭
- 该 socket 上未完成的连接（如半连接队列中的 SYN）需要迁移
- BPF 程序选择一个新的 listener 接收这些连接
- `migrating_sk` 指向被关闭的 socket

### attach 方式

sk_reuseport 程序不使用 `bpf_link`，而是通过 `setsockopt`：

```c
/* attach BPF 程序到 reuseport 组 */
int prog_fd = bpf_program__fd(prog);
setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
           &prog_fd, sizeof(prog_fd));

/* 替换为另一个 BPF 程序（只需再次 setsockopt） */
int new_fd = bpf_program__fd(new_prog);
setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
           &new_fd, sizeof(new_fd));
```

只需 attach 到组中的一个 socket，对整个 reuseport 组生效。

### 与其他 socket BPF 类型的对比

| 类型 | SEC | 作用 | attach 方式 |
|------|-----|------|------------|
| `CGROUP_SOCK_ADDR` | `cgroup/connect4` 等 | 拦截/改写 connect/bind 地址 | `bpf_program__attach_cgroup` |
| `SK_LOOKUP` | `sk_lookup` | 替代 reuseport 的 L7 代理 | `bpf_program__attach_sk_lookup` |
| **`SK_REUSEPORT`** | **`sk_reuseport`** | **自定义 reuseport 选择** | **`setsockopt SO_ATTACH_REUSEPORT_EBPF`** |

## 文件结构

```
81-sk-reuseport/
├── Makefile              # APP := sk-reuseport
├── sk-reuseport.h          # 共享：event 结构、NUM_SOCKETS 常量
├── sk-reuseport.bpf.c      # 2 个 BPF 程序（select + migrate）
├── sk-reuseport.c          # 加载器 + 多 listener 测试
└── README.md
```
