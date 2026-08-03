# 58-iter-open-coded — Open-coded Iterator（bpf_for / bpf_repeat）

## 概述

演示 BPF open-coded iterator：`bpf_for`、`bpf_repeat` 宏。这些是 kfunc，可在任意 BPF 程序类型中使用（本示例用 tracepoint）。

### 设计

- **ringbuf 输出**（非 trace_pipe）：结果通过 ringbuf 发到用户态，不刷屏
- **PID 过滤**：`target_pid` 全局变量，仅响应指定子进程的 syscall
- **自包含**：fork 子进程触发 openat/read/write，自动设置 target_pid

### 三个程序

| 程序 | 宏 | 触发 syscall | 功能 |
|---|---|---|---|
| `sum_squares` | `bpf_for(i, 0, 10)` | openat | 计算 0..9 的平方和 = 285 |
| `fill_array` | `bpf_for(i, 0, 10)` | read | 填充数组（验证器自动证明范围安全） |
| `repeat_demo` | `bpf_repeat(5)` | write | 执行 5 次循环计数 = 5 |

## 编译与运行

```bash
make -C src/58-iter-open-coded
sudo ./src/58-iter-open-coded/iter-oc
```

## 输出示例

```
Open-coded iterators demo (target PID 281213):

  bpf_for: sum of squares 0..9 = 285
  bpf_for: arr[5] = 25
  bpf_repeat: count = 5

Done. All 3 open-coded iterators executed successfully.
```

## 教学概念

- `bpf_for(i, start, end)` — 数字迭代器，验证器证明 i ∈ [start, end)
- `bpf_repeat(N)` — 执行 N 次循环
- open-coded iterator 是 kfunc 三元组（new/next/destroy），非程序类型
- 验证器在 `next` 调用处分叉验证（NULL/非 NULL 两路）
- 与 `SEC("iter/...")` 程序类型的区别：open-coded 在 BPF 内部循环，程序类型由用户态 read 触发
- **PID 过滤 + ringbuf**：避免高频 syscall 刷屏，仅响应目标进程
