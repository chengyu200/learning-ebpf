# 66-struct-ops-tcp-cc — 用 BPF struct_ops 实现 TCP 拥塞控制

## 概述

用 `BPF_PROG_TYPE_STRUCT_OPS` 实现一个完整的、可用的 TCP 拥塞控制算法 `bpf_reno_trace`——以 Reno 为基础（委托内核 ksym），叠加 CC 行为追踪（ringbuf 输出 cwnd 变化和状态变迁）。

### struct_ops 机制

```
┌─ BPF 程序 ──────────────────────────────────────────────┐
│  SEC("struct_ops") cc_cong_avoid(sk, ack, acked)       │
│  SEC("struct_ops") cc_ssthresh(sk)                      │
│  SEC("struct_ops") cc_init(sk)  / cc_release(sk) / ... │
│                                                         │
│  SEC(".struct_ops")                                     │
│  struct tcp_congestion_ops bpf_reno_trace = {           │
│    .name = "bpf_reno_trace",                            │
│    .cong_avoid = (void *)cc_cong_avoid,                 │
│    ...                                                  │
│  }                                                      │
└──────────────────────────┬──────────────────────────────┘
                           │ libbpf 自动注册
                           ▼
┌─ 内核 TCP 栈 ───────────────────────────────────────────┐
│  tcp_register_congestion_control(&bpf_reno_trace)      │
│  → /proc/sys/net/ipv4/tcp_available_congestion_control │
│  → setsockopt(TCP_CONGESTION, "bpf_reno_trace")        │
│  → 内核调用 BPF 回调                                    │
└─────────────────────────────────────────────────────────┘
```

### 两个关键 SEC

| SEC | 类型 | 作用 |
|---|---|---|
| `SEC("struct_ops")` | 程序段 | 实现单个回调（如 `cong_avoid`） |
| `SEC(".struct_ops")` | 数据段 | 声明完整 vtable + `.name`，触发内核注册 |

### 实现的回调

| 回调 | 实现方式 | 说明 |
|---|---|---|
| `init` | 日志 | 连接初始化时触发 |
| `cong_avoid` | 委托 `tcp_reno_cong_avoid` + 记录 cwnd | 拥塞避免核心逻辑 |
| `ssthresh` | 委托 `tcp_reno_ssthresh` | 慢启动阈值 |
| `set_state` | 日志 | CC 状态变迁（Open→CWR 等） |
| `undo_cwnd` | 委托 `tcp_reno_undo_cwnd` | 撤销 cwnd |
| `release` | 日志 | 连接释放 |

### 委托内核 ksym

BPF 程序可以直接调用内核导出的 CC 函数（通过 `__ksym`）：

```c
extern void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked) __weak __ksym;
extern u32 tcp_reno_ssthresh(struct sock *sk) __weak __ksym;
extern u32 tcp_reno_undo_cwnd(struct sock *sk) __weak __ksym;
```

## 编译与运行

```bash
make -C src/66-struct-ops-tcp-cc
sudo ./src/66-struct-ops-tcp-cc/tcp-cc
```

程序自包含：自动 fork TCP echo server + client，选择 BPF CC 传输数据。

## 输出示例

```
CC 'bpf_reno_trace' registered: reno cubic bpf_reno_trace
Set TCP_CONGESTION=bpf_reno_trace on client socket

Echo received: Hello from BPF CC test!

--- CC Events ---
[INIT]    pid=1234   CC initialized for connection
[CWND]    pid=1234   cwnd=2     ssthresh=2147483647
[CWND]    pid=1234   cwnd=4     ssthresh=2147483647
[CWND]    pid=1234   cwnd=5     ssthresh=2147483647
[STATE]   pid=1234   -> Open
[RELEASE] pid=1234   connection released
```

## 文件结构

```
66-struct-ops-tcp-cc/
├── Makefile
├── README.md
├── tcp_cc.h              # 共享：事件结构体 + CC 名称
├── tcp_cc.bpf.c          # struct_ops 程序 + .struct_ops vtable
└── tcp_cc.c              # 用户态：注册验证 + TCP 测试 + ringbuf
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `BPF_PROG_TYPE_STRUCT_OPS` | 用 BPF 替换内核子系统的函数指针表 |
| `SEC("struct_ops")` | 声明 BPF 程序作为 ops 回调 |
| `SEC(".struct_ops")` | 声明完整 vtable，libbpf 自动注册 |
| `bpf_map__attach_struct_ops` | 注册 struct_ops 到内核（skeleton 自动调用） |
| `__weak __ksym` | 声明内核符号，BPF 程序可直接调用 |
| `tcp_congestion_ops` | TCP CC 接口结构体 |
| `setsockopt(TCP_CONGESTION)` | 用户态选择 CC 算法 |
| `/proc/sys/net/ipv4/tcp_available_congestion_control` | 查看已注册的 CC |

## 真实场景

| 工具/项目 | 使用方式 |
|---|---|
| Google BBR v3 BPF | 用 struct_ops 实现 BBR CC 算法 |
| Cilium | 用 struct_ops 实现 DCTCP 变体 |
| 本示例 | Reno 委托 + 追踪，展示完整 struct_ops CC 开发流程 |

## 与现有 stub 的对比

| 维度 | features/struct_ops（stub） | 本示例 |
|---|---|---|
| 回调数 | 1（仅 init） | 6（完整 CC） |
| 可用性 | ❌ 不可用 | ✅ 可用 CC 算法 |
| 委托 ksym | ❌ | ✅ tcp_reno_* |
| 事件输出 | bpf_printk | ringbuf 结构化事件 |
| 用户态验证 | 无 | 验证注册 + setsockopt + 传输 |
