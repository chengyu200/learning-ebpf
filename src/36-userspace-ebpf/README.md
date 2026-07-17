# 36-userspace-ebpf

用户态 eBPF 运行时（如 bpftime、ubpf）。

## 为什么本机无法运行

本示例需要安装额外的用户态 eBPF 运行时（如 [bpftime](https://github.com/eunomia-bpf/bpftime) 或 [ubpf](https://github.com/iovisor/ubpf)），本机未安装。

## 原教程做什么

演示在用户态运行 eBPF 程序（而非内核），降低 uprobe 开销，实现进程间通信加速。

## 参考

- 原教程：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/36-userspace-ebpf>
- bpftime：<https://github.com/eunomia-bpf/bpftime>
