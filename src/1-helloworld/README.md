# 1-helloworld

eBPF 版 "Hello World"：最小骨架流程。

## 做什么

- 内核态：在 `sys_enter_execve` tracepoint 上挂钩，每次有进程执行 `execve` 时用 `bpf_trace_printk` 输出一行 `Hello eBPF! pid=... comm=...`。
- 用户态：用 libbpf 打开并加载骨架、attach，然后把内核 trace pipe 的内容拷贝到 stdout。

## 教学概念

- libbpf 骨架（skeleton）的 `open_and_load` → `attach` → 销毁 生命周期。
- `bpf_trace_printk` 与 `/sys/kernel/tracing/trace_pipe` 这条最简单的调试通道。
- tracepoint 挂载点 `SEC("tp/syscalls/sys_enter_execve")`。

## 运行

```bash
make -C src/1-helloworld
sudo ./src/1-helloworld/helloworld
# 任意命令触发，例如另开终端：ls
```

也可直接查看原始 trace：

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

> `bpf_trace_printk` 格式串必须是栈上的独立 `char` 数组（见 `helloworld.bpf.c`），且最多 3 个参数——这是其与 `printf` 的关键区别。
