# 45-scx-nest

实现 `scx_nest` 调度器。

## 为什么本机无法运行

同 44-scx-simple：本机内核未启用 sched_ext（`CONFIG_BPF_SCHED` / `CONFIG_EXT_SCHED_CLASS` 未设置）。

## 原教程做什么

实现 scx_nest 调度器，一种基于嵌套（nesting）的调度策略，优化延迟敏感工作负载。

## 参考

- 原教程：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/45-scx-nest>
