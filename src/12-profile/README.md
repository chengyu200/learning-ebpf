# 12-profile

CPU 采样 profiling，采集内核态与用户态栈并输出 Top N。

## 做什么

- 内核态：`SEC("perf_event")` 程序在每次 perf 采样时用 `bpf_get_stack` 采集内核栈与用户栈，通过 ring buffer 发送到用户态。
- 用户态：对每个 CPU 打开一个 `PERF_COUNT_SW_CPU_CLOCK` perf 事件，用 `bpf_program__attach_perf_event` 把 BPF 程序挂上去；按栈签名聚合计数，结束时打印 Top N。

## 教学概念

- perf_event 类 BPF 程序与 `bpf_program__attach_perf_event` 的手动 attach。
- `perf_event_open` 系统调用（`PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_CPU_CLOCK`，按频率采样）。
- `bpf_get_stack` 采集内核/用户栈、栈签名聚合。
- 内核符号化：解析 `/proc/kallsyms` 后二分查找。

## 运行

```bash
make -C src/12-profile
sudo ./src/12-profile [duration_s] [topN] [freq]
# 例：采样 5 秒，输出 Top 10，99Hz
sudo ./src/12-profile 5 10 99
```

## 与原教程差异

原教程用户态为 **Rust**（libblazesym 符号化）；本仓库改纯 C，内核栈走 `/proc/kallsyms`，用户态地址以原始十六进制 + pid/comm 输出（不解析）。
