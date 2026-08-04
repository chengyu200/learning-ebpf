# 65-tp-vs-raw-tp

对比 `BPF_PROG_TYPE_TRACEPOINT` 和 `BPF_PROG_TYPE_RAW_TRACEPOINT` 的写法差异和性能差异。

## 做什么

两个 BPF 程序挂载到同一个 tracepoint（`sched/sched_switch`），功能相同（统计进程切换次数），但写法和上下文不同。用户态每秒读取 per-CPU 统计，对比事件数和执行开销。

支持两种模式：
- **FULL**（默认）：计数 + 读取字段，对比 BPF 程序内部开销
- **COUNT-ONLY**（`--count-only`）：只计数跳过字段读取，对比内核侧开销

## 用法

```bash
make -C src/65-tp-vs-raw-tp

# FULL 模式（计数 + 读取字段）
sudo ./src/65-tp-vs-raw-tp/compare          # 默认 10 秒
sudo ./src/65-tp-vs-raw-tp/compare 5        # 5 秒

# COUNT-ONLY 模式（只计数，跳过字段读取）
sudo ./src/65-tp-vs-raw-tp/compare 5 --count-only
```

## 两种类型的核心差异

| 特性 | TRACEPOINT (`tp/`) | RAW_TRACEPOINT (`raw_tp/`) |
|------|---------------------|---------------------------|
| **SEC 名** | `tp/sched/sched_switch` | `raw_tp/sched_switch` |
| **上下文** | `struct trace_event_raw_sched_switch *`（类型化，已解析字段） | `struct bpf_raw_tracepoint_args *`（`args[]` 原始参数） |
| **字段访问** | `ctx->prev_pid`（直接访问） | `BPF_CORE_READ(args[0], pid)`（需 CO-RE 读取） |
| **数据来源** | 内核 tracepoint 格式化后的数据 | 内核函数的原始参数 |
| **内核侧开销** | 较高（先格式化 tracepoint 数据再调用 BPF） | **较低**（跳过格式化，直接传原始参数） |
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
    __u32 prev_pid = ctx->prev_pid;   // 一次内存读
    __u32 next_pid = ctx->next_pid;
}
```

### RAW_TRACEPOINT（原始参数）

```c
SEC("raw_tp/sched_switch")
int count_raw_tp(struct bpf_raw_tracepoint_args *ctx)
{
    /* 从原始参数中获取 task_struct 指针 */
    struct task_struct *prev = (struct task_struct *)ctx->args[0];
    /* 需用 BPF_CORE_READ 读取 pid（CO-RE + bpf_probe_read） */
    __u32 prev_pid = BPF_CORE_READ(prev, pid);
}
```

## 性能对比结果

在本机（aarch64, kernel 7.0）上实测：

### FULL 模式（计数 + 读取字段）

```
═══════════════════════════════════════════════════════════════
  Summary (FULL)
═══════════════════════════════════════════════════════════════
  TRACEPOINT:     35029 events, 3.258 ms total, 93.0 ns/evt
  RAW_TRACEPOINT: 35029 events, 10.768 ms total, 307.4 ns/evt
  TP is 69.7% faster (93.0 vs 307.4 ns/evt)
  Events match: YES
═══════════════════════════════════════════════════════════════
```

**TP 更快**：直接访问 `ctx->prev_pid`（一次内存读）远比 `BPF_CORE_READ(prev, pid)`（CO-RE 重定位 + `bpf_probe_read` 内核内存读取）便宜。

### COUNT-ONLY 模式（只计数，跳过字段读取）

```
═══════════════════════════════════════════════════════════════
  Summary (COUNT-ONLY)
═══════════════════════════════════════════════════════════════
  TRACEPOINT:     35344 events, 2.675 ms total, 75.7 ns/evt
  RAW_TRACEPOINT: 35343 events, 1.988 ms total, 56.2 ns/evt
  RAW_TP is 25.7% faster (56.2 vs 75.7 ns/evt)
═══════════════════════════════════════════════════════════════
```

**RAW_TP 更快**：跳过了内核的 tracepoint 数据格式化开销，TP 在调用 BPF 程序前需要先格式化数据。

## 两种开销来源

| 开销来源 | TRACEPOINT | RAW_TRACEPOINT |
|---------|------------|----------------|
| **内核侧**（调用 BPF 前） | 格式化 tracepoint 数据（~20ns 额外） | 跳过格式化（直接传 args） |
| **BPF 程序内**（读字段） | `ctx->prev_pid`（~0ns，直接访问） | `BPF_CORE_READ(prev, pid)`（~200ns，CO-RE + probe_read） |
| **总开销** | 内核格式化 + 直接访问 | 无格式化 + CO-RE 读取 |

FULL 模式下 BPF 程序内的 CO-RE 开销占主导（TP 赢）。
COUNT-ONLY 模式下内核格式化开销占主导（RAW_TP 赢）。

## 什么时候用哪个？

| 场景 | 推荐类型 | 原因 |
|------|---------|------|
| 需要读取 tracepoint 字段 | **TRACEPOINT** | 字段已格式化，直接访问，避免 CO-RE 开销 |
| 只计数 / 不需要字段 | **RAW_TRACEPOINT** | 跳过内核格式化开销，内核侧更快 |
| 需要原始内核结构体中的其他字段 | **RAW_TRACEPOINT** | 直接拿到 task_struct*，可读任意字段 |
| 需要修改参数 | **RAW_TRACEPOINT** | `raw_tp.w+` 可修改（RAW_TRACEPOINT_WRITABLE） |
| tracepoint format 跨内核不稳定 | **RAW_TRACEPOINT** | 依赖函数签名，更稳定 |

## 实现细节

### BPF 程序（`compare.bpf.c`）

- `const volatile bool read_fields`：控制是否读取字段（用户态在 load 前设置）
  - `true`（默认）：读 `ctx->prev_pid` / `BPF_CORE_READ(prev, pid)`，偶尔 `bpf_printk`
  - `false`（`--count-only`）：跳过所有字段读取，只 `count++`
- 两个 per-CPU array map 分别统计两种程序的 `count` + `total_ns`
- `bpf_ktime_get_ns()` 测量每个程序的执行时间

### 用户态（`compare.c`）

- `--count-only` 参数设置 `skel->rodata->read_fields = false`
- 每秒读取 per-CPU map，计算 delta 并打印对比
- 最终输出总结：总事件数、平均每事件开销、性能差异百分比
