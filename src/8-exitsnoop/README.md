# 8-exitsnoop

监控进程退出，用 **ring buffer** 输出。与 [7-execsnoop](../7-execsnoop) 对照。

## 做什么

- 内核态：
  - `sched_process_fork`：记录进程起始时间戳（哈希表，键为 pid）；
  - `sched_process_exit`：仅对整个进程退出（`pid==tid`）计算存活时长，读取 exit_code 与 ppid，通过 ring buffer 发送。
- 用户态：轮询 ring buffer 打印。

## 教学概念

- **ring buffer**（`BPF_MAP_TYPE_RINGBUF`）+ `bpf_ringbuf_reserve/submit`，零拷贝、全局共享。
- fork + exit 配合哈希表追踪进程生命周期。
- 从 `task_struct` 读取 `exit_code`、`real_parent`。

## 运行

```bash
make -C src/8-exitsnoop
sudo ./src/8-exitsnoop/exitsnoop
# 触发：另开终端运行任何会退出的命令，例如 sh -c 'exit 7'
```
