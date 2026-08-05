# 67-syscall-prog — BPF syscall RPC 键值存储

## 概述

用 `BPF_PROG_TYPE_SYSCALL` 实现一个内核态键值存储——用户态通过 `BPF_PROG_RUN` 传入操作请求，BPF 程序在内核中操作 HASH map 并返回结果。相当于一个"内核态 mini-Redis"。

### BPF_PROG_TYPE_SYSCALL 的独特性

| 特性 | 说明 |
|---|---|
| **用户态主动触发** | 通过 `bpf(BPF_PROG_RUN)` 调用，非被动响应内核事件 |
| **上下文由用户态提供** | `ctx_in` 传入任意数据结构，BPF 程序直接访问 |
| **返回值传回用户态** | BPF 程序的 `return` 值通过 `retval` 传回 |
| **不需要 attach** | 加载即可用，无 hook 点 |
| **默认 sleepable** | 可使用 `bpf_copy_from_user` 等可睡眠 helper |
| **独有 helper** | `bpf_sys_bpf`（从 BPF 内执行 bpf 系统调用）、`bpf_sys_close` |

### 工作流程

```
┌─ 用户态 (rpc_kv.c) ──────────────────────────────┐
│  交互式 CLI:                                     │
│    > put 42 100       → BPF_PROG_RUN(op=PUT)    │
│    > get 42           → BPF_PROG_RUN(op=LOOKUP) │
│    > del 42           → BPF_PROG_RUN(op=DELETE) │
│    > stats            → 读取 percpu stats map    │
│                                                   │
│  bpf_prog_test_run_opts(prog_fd, {               │
│      .ctx_in = &req,                             │
│      .ctx_size_in = sizeof(req),                │
│  }) → retval = 结果                              │
└──────────────────┬───────────────────────────────┘
                   │ BPF_PROG_RUN
                   ▼
┌─ BPF 内核态 (rpc_kv.bpf.c) ─────────────────────┐
│  SEC("syscall")                                  │
│  int handle_rpc(struct rpc_req *req) {           │
│    switch (req->op) {                           │
│      case PUT:    bpf_map_update_elem(&store)   │
│      case LOOKUP: bpf_map_lookup_elem(&store)   │
│      case DELETE: bpf_map_delete_elem(&store)   │
│    }                                             │
│    return result;                                │
│  }                                               │
│  Maps: store(HASH) + stats(PERCPU_ARRAY)         │
└───────────────────────────────────────────────────┘
```

## 编译与运行

```bash
make -C src/67-syscall-prog
sudo ./src/67-syscall-prog/rpc_kv
```

交互式 CLI：
```
> put 42 100
> put 7 777
> get 42
> stats
> del 42
> quit
```

## 输出示例

```
# ./rpc_kv 
BPF syscall RPC KV store loaded.
  prog_fd=6  store(map_fd=3)  stats(map_fd=4)

Commands: put <key> <value> | get <key> | del <key> | stats | quit

> put 42 100
  PUT key=42 value=100 -> OK (0)
> get 42
  LOOKUP key=42 -> value=100
> get 99
  LOOKUP key=99 -> NOT FOUND (-2)
> put 7 777
  PUT key=7 value=777 -> OK (0)
> stats

  --- Operation Stats ---
  PUT      2  (CPU0=0 CPU1=0 CPU2=0 CPU3=2)
  LOOKUP   2  (CPU0=0 CPU1=0 CPU2=0 CPU3=2)
  DELETE   0  (CPU0=0 CPU1=0 CPU2=0 CPU3=0)
> del 42
  DELETE key=42 -> OK (0)
> del 42
  DELETE key=42 -> NOT FOUND (-2)
> quit

  Cleanup. Goodbye.

```

## 文件结构

```
67-syscall-prog/
├── Makefile
├── README.md
├── rpc_kv.h              # 共享：rpc_req 结构体 + 操作码 + 错误码
├── rpc_kv.bpf.c          # SEC("syscall") 程序 + HASH map + PERCPU stats
└── rpc_kv.c              # 用户态：交互式 CLI + bpf_prog_test_run_opts
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `BPF_PROG_TYPE_SYSCALL` | 用户态主动触发的 BPF 程序类型 |
| `SEC("syscall")` | 声明 syscall 程序，自动 sleepable |
| `bpf_prog_test_run_opts` | 用户态通过 BPF_PROG_RUN 触发执行 |
| `ctx_in` / `retval` | 用户态↔BPF 的数据通道 |
| 不需要 attach | syscall 程序无 hook 点，加载即可用 |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | per-CPU 操作统计 |
| 内核态 RPC 模式 | BPF 程序作为内核服务，用户态通过 BPF_PROG_RUN 调用 |

## 真实场景

| 场景 | 描述 |
|---|---|
| **Light Skeleton** | `bpftool gen skeleton` 生成的加载器是 syscall 程序，用 `bpf_sys_bpf` 在内核内加载其他 BPF 程序 |
| **BPF Preload** | 内核模块在启动时预加载 BPF 程序 |
| **内核态 RPC** | 用户态传入请求，BPF 在内核中执行复杂操作（如批量 map 操作、BTF 解析） |
| **减少系统调用开销** | 一次 BPF_PROG_RUN 完成多次 map 操作，减少用户态-内核态切换 |

## 与其他示例的对比

| 维度 | 54-httpstat | 63-tp-btf | **67-syscall-prog** |
|---|---|---|---|
| 触发方式 | 被动（socket filter） | 被动（内核 tracepoint） | **主动（用户态 BPF_PROG_RUN）** |
| 上下文 | 内核提供 | 内核提供 | **用户态提供** |
| 用途 | 观测 | 观测 | **计算/存储（RPC）** |
| 返回值 | 不影响 | 不影响 | **返回结果给用户态** |
| Attach | 需要 | 需要 | **不需要** |
