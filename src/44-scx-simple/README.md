# 44-scx-simple

BPF 调度器（sched_ext）入门。

## 为什么本机无法运行

本机内核 `CONFIG_BPF_SCHED` 未设置、`CONFIG_EXT_SCHED_CLASS` 未设置，`/sys/kernel/sched_ext/state` 为 disabled。sched_ext 调度器需要内核启用 `CONFIG_SCHED_CLASS_EXT`。

## 原教程做什么

用 BPF 实现一个简单的 sched_ext 调度器，替换默认 CFS 调度策略。

## 参考

- 原教程：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/44-scx-simple>
- sched_ext 文档：<https://github.com/sched-ext/scx>
