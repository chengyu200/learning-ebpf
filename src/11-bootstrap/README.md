# 11-bootstrap

用 libbpf 开发用户态程序，追踪 `exec()` 与 `exit()`。这是原教程“高级示例”的开篇，也是 libbpf-bootstrap 的经典示例。

## 做什么

- 内核态：`sched_process_exec` 记录新进程（文件名、pid、ppid）；`sched_process_exit` 计算进程生命周期并读取退出码，两者都通过 ring buffer 发送到用户态。
- 用户态：用 argp 解析 `--duration`（最小存活时长过滤）和 `--verbose`，加载/attach 骨架，轮询 ring buffer 打印。

## 教学概念

- libbpf 骨架完整生命周期：`open` → 设置 rodata → `load` → `attach` → 轮询 → `destroy`。
- `BPF_MAP_TYPE_RINGBUF` 与 `bpf_ringbuf_reserve/submit`。
- 用 `const volatile` 全局变量（`min_duration_ns`）做配置。
- 读取 `__data_loc_filename` tracepoint 字段、`BPF_CORE_READ(task, real_parent, tgid)`。

## 运行

```bash
make -C src/11-bootstrap
sudo ./src/11-bootstrap
# 或只看存活超过 100ms 的进程：
sudo ./src/11-bootstrap -d 100
```
