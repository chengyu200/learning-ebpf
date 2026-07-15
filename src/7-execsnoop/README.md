# 7-execsnoop

捕获进程执行（`execve`），用 **perf event array** 输出。与 [8-exitsnoop](../8-exitsnoop) 对照。

## 做什么

- 内核态：在 `sched_process_exec` tracepoint 上捕获 pid/ppid/comm/filename，用 `bpf_perf_event_output` 发送到 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`。
- 用户态：用 `perf_buffer__new` / `perf_buffer__poll` 接收事件并打印。

## 教学概念

- **perf buffer**（perf event array）这条较老的事件输出通道。
- 读取 tracepoint 的 `__data_loc_filename` 字段（低 16 位为相对偏移）。
- `BPF_CORE_READ(task, real_parent, tgid)` 获取父进程。

## 运行

```bash
make -C src/7-execsnoop
sudo ./src/7-execsnoop/execsnoop
# 任意执行命令触发，例如另开终端：ls / bash
```

## perf buffer vs ring buffer

perf buffer 是每 CPU 一个缓冲区、按事件拷贝；ring buffer（示例 8）是全局共享、零拷贝预留，是新内核的推荐方式。本仓库刻意保留两者以便对比学习。
