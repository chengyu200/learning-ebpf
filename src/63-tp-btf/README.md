# 63-tp-btf — BTF-based Raw Tracepoint (tp_btf)

## 概述

用 `SEC("tp_btf/...")` 追踪进程生命周期（exec/fork/exit），展示现代 BPF tracepoint 挂载方式的优势：类型安全的参数访问、无需 `__data_loc` 解析、与 raw_tracepoint 相同的性能。

## tp_btf vs tp vs raw_tp 对比

| 特性 | `SEC("tp/...")` | `SEC("raw_tp/...")` | `SEC("tp_btf/...")` |
|---|---|---|---|
| 程序类型 | `BPF_PROG_TYPE_TRACEPOINT` | `BPF_PROG_TYPE_RAW_TRACEPOINT` | `BPF_PROG_TYPE_TRACING` (`BPF_TRACE_RAW_TP`) |
| 上下文 | `trace_event_raw_*` 结构体 | `bpf_raw_tracepoint_args`（无类型） | **原始内核参数**（有类型） |
| 参数访问 | `ctx->field`（需解析 `__data_loc`） | `ctx->args[0]`（无类型指针） | **`BPF_PROG` 宏，命名参数** |
| BTF 依赖 | 需要 BTF | 不需要 BTF | **需要 BTF** |
| 性能 | 中等（有 trace_event 开销） | 最高 | **最高（同 raw_tp，但有类型）** |
| attach | `attach_tp` | `attach_raw_tp` | **`attach_trace`（BTF ID 自动解析）** |

### tp_btf 的核心优势

`tp_btf` 兼具 `raw_tp` 的高性能和 `fentry` 的类型安全——参数直接以内核函数签名的形式提供（通过 `BPF_PROG` 宏），无需从 `trace_event_raw_*` 结构体手动解析 `__data_loc` 字段。

## 与 11-bootstrap 的对比

| 维度 | 11-bootstrap (`tp/`) | 本示例 (`tp_btf/`) |
|---|---|---|
| 获取 filename | `ctx->__data_loc_filename & 0xFFFF` + 偏移读取 | `BPF_CORE_READ(bprm, filename)` |
| 获取 pid | `bpf_get_current_pid_tgid() >> 32` | `BPF_CORE_READ(task, pid)` |
| fork 参数 | `ctx->parent_pid` / `ctx->child_pid` | `BPF_PROG(parent, child)` 直接访问 |
| exit 参数 | `ctx->pid` / `ctx->comm` | `BPF_PROG(task)` 直接读取 |

## 编译与运行

```bash
make -C src/63-tp-btf
sudo ./src/63-tp-btf/tp-btf

# 另开终端触发事件
ls /usr/bin/cat
sleep 1 &
```

## 输出示例

```
tp-btf: tracing process lifecycle (tp_btf). Ctrl-C to stop.

[EXEC] pid=12345 ppid=12340 comm=ls filename=/usr/bin/ls
[FORK] pid=12346 ppid=12345 comm=ls
[EXIT] pid=12345 comm=ls exit_code=0
```

## 文件结构

```
63-tp-btf/
├── Makefile
├── README.md
├── tp-btf.h              # 共享事件结构体
├── tp-btf.bpf.c          # 3 个 tp_btf 程序 + ringbuf
└── tp-btf.c              # 用户态：attach + ringbuf 轮询
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `SEC("tp_btf/...")` | BTF-based raw tracepoint，程序类型为 BPF_PROG_TYPE_TRACING |
| `BPF_TRACE_RAW_TP` | attach type，通过 BTF ID 自动解析 tracepoint |
| `BPF_PROG` 宏 | 提供类型化的命名参数，无需手动解析上下文 |
| `BPF_CORE_READ` | CO-RE 读取内核结构体字段（`task->pid`、`bprm->filename`） |
| `bpf_probe_read_kernel_str` | 读取内核字符串到栈缓冲区 |
| 对比 `tp/` | tp_btf 无需 `__data_loc` 解析，代码更简洁 |
| 对比 `raw_tp/` | tp_btf 有类型安全参数，而非 `args[0]` 无类型指针 |
