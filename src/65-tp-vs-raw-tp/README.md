# 65-tp-vs-raw-tp

对比 `BPF_PROG_TYPE_TRACEPOINT` 和 `BPF_PROG_TYPE_RAW_TRACEPOINT` 的写法差异和性能差异。

## 做什么

两个 BPF 程序挂载到同一个 tracepoint（`sched/sched_switch`），功能相同（统计进程切换次数），但写法和上下文不同。用户态每秒读取 per-CPU 统计，对比事件数和执行开销。

## 两种类型的核心差异

| 特性 | TRACEPOINT (`tp/`) | RAW_TRACEPOINT (`raw_tp/`) |
|------|---------------------|---------------------------|
| **SEC 名** | `tp/sched/sched_switch` | `raw_tp/sched_switch` |
| **上下文** | `struct trace_event_raw_sched_switch *`（类型化，已解析字段） | `struct bpf_raw_tracepoint_args *`（`args[]` 原始参数） |
| **字段访问** | `ctx->prev_pid`（直接访问） | `BPF_CORE_READ(args[0], pid)`（需 CO-RE 读取） |
| **数据来源** | 内核 tracepoint 格式化后的数据 | 内核函数的原始参数 |
| **内核开销** | 较高（先格式化 tracepoint 数据再调用 BPF） | 较低（跳过格式化，直接传原始参数） |
| **BPF 程序开销** | 较低（直接访问字段，无需 CO-RE） | **较高**（需 BPF_CORE_READ 从 task_struct 读取） |
| **helper 数量** | 1989 个 | 912 个 |
| **可写性** | 不可修改参数 | `raw_tp.w+` 可修改（RAW_TRACEPOINT_WRITABLE） |

## 写法对比

### TRACEPOINT（类型化上下文）

```c
SEC("tp/sched/sched_switch")
int count_tp(struct trace_event_raw_sched_switch *ctx)
{
    /* 直接访问已解析的字段，无需 CO-RE */
    __u32 prev_pid = ctx->prev_pid;
    __u32 next_pid = ctx->next_pid;
    /* ... */
}
```

### RAW_TRACEPOINT（原始参数）

```c
SEC("raw_tp/sched_switch")
int count_raw_tp(struct bpf_raw_tracepoint_args *ctx)
{
    /* 从原始参数中获取 task_struct 指针 */
    struct task_struct *prev = (struct task_struct *)ctx->args[0];
    struct task_struct *next = (struct task_struct *)ctx->args[1];
    /* 需用 BPF_CORE_READ 读取 pid */
    __u32 prev_pid = BPF_CORE_READ(prev, pid);
    __u32 next_pid = BPF_CORE_READ(next, pid);
    /* ... */
}
```

## 性能对比结果

在本机（aarch64, kernel 7.0）上实测：

```
═══════════════════════════════════════════════════════════════
  Summary
═══════════════════════════════════════════════════════════════
  TRACEPOINT:     19085 events, 1.802 ms total, 94.4 ns/evt
  RAW_TRACEPOINT: 19085 events, 9.299 ms total, 487.2 ns/evt
  TP is 80.6% faster (94.4 vs 487.2 ns/evt)
  Events match: YES
═══════════════════════════════════════════════════════════════
```

### 为什么 TRACEPOINT 更快？

虽然 RAW_TRACEPOINT **跳过了内核的 tracepoint 数据格式化**（内核侧开销更低），但在 BPF 程序内部：
- **TRACEPOINT**：直接访问 `ctx->prev_pid`（一次内存读）
- **RAW_TRACEPOINT**：需要 `BPF_CORE_READ(prev, pid)`（CO-RE 重定位 + `bpf_probe_read` 内核内存读取，开销大得多）

所以**BPF 程序总开销**取决于：
- 如果只需要 tracepoint 格式化后的字段 → **TRACEPOINT 更快**（避免 CO-RE）
- 如果需要原始内核结构体中的其他字段 → **RAW_TRACEPOINT 可能更快**（避免格式化 + CO-RE 一起做）

### 什么时候用 RAW_TRACEPOINT？

- 需要访问 tracepoint format 中没有的字段（如 `task_struct->mm`）
- 需要修改参数（`raw_tp.w+`）
- tracepoint format 在不同内核版本间不稳定
- 只需要计数（不需要读任何字段，raw_tp 的内核侧开销更低）

## 运行

```bash
make -C src/65-tp-vs-raw-tp
sudo ./src/65-tp-vs-raw-tp        # 默认 10 秒
sudo ./src/65-tp-vs-raw-tp 5      # 5 秒
```
