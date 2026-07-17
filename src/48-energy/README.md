# 48-energy

进程级能耗监控。

## 为什么本机无法运行

本示例需要 `intel-rapl` powercap 接口（`/sys/class/powercap/intel-rapl*`）来读取能耗计数器。本机为 aarch64、无 powercap 硬件支持，故仅提供 README 说明。

## 原教程做什么

通过 tracepoint `power/cpu_energy` 或读取 `intel-rapl`，按进程累加能耗并输出 Top N。

## 在支持的机器上运行

需要 Intel CPU + `CONFIG_PERF_EVENTS` + `intel-rapl` 模块加载。原教程基于 libbpf C 实现（`energy.bpf.c` + `energy.c`），可在 [原仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/48-energy) 获取完整代码。

## 关键概念

- 能耗计数（RAPL - Running Average Power Limit）：MSR 或 powercap sysfs。
- 进程关联：通过 `task_struct` 关联能耗事件到 PID。
- `BPF_MAP_TYPE_HASH` 按 pid 聚合。
