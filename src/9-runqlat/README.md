# 9-runqlat

捕获调度运行队列延迟，按 log2 直方图记录。

## 做什么

- 内核态：
  - `sched_wakeup` / `sched_wakeup_new`：任务变为可运行，记录时间戳（哈希表，键为 pid）；
  - `sched_switch`：当 `next_pid` 是我们记录过的任务，计算延迟（唤醒→真正运行），按 log2 分桶累加到 array map。
- 用户态：Ctrl-C 时遍历 array map 打印直方图。

## 教学概念

- `BPF_MAP_TYPE_ARRAY` 与轮询读取（无 perf/ring 输出）。
- log2 直方图分桶（用 `64 - __builtin_clzll(x)` 求 floor(log2)）。
- 运行队列延迟（run queue latency）的性能分析意义。

## 运行

```bash
make -C src/9-runqlat
sudo ./src/9-runqlat/runqlat
# 运行几秒后按 Ctrl-C 打印直方图
```

输出示例（单位：微秒）：

```
range        count      : percent  |graph
2^2  - 2^3  3693       : 100.00% |****************************************
2^3  - 2^4  3412       :   92.39% |****************************************
```
