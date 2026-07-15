# 18-further-reading

本目录不含代码，仅为进阶参考资料索引。

## 概念回顾

lesson 1–17 覆盖了 eBPF 的核心机制：tracepoint / kprobe / fentry / uprobe / USDT / perf event array / ring buffer / 直方图 / 哈希表 / array map / TC / XDP / LSM / 内存泄漏追踪 / 网络与中断统计。

## 进阶学习资源

### 内核与 eBPF 子系统
- BPF & libbpf 文档：<https://docs.kernel.org/bpf/>
- libbpf 仓库与示例：<https://github.com/libbpf/libbpf>，特别是 `libbpf-bootstrap`：<https://github.com/libbpf/libbpf-bootstrap>
- BPF Compiler Collection (BCC) libbpf-tools：<https://github.com/iovisor/bcc/tree/master/libbpf-tools>
- BPF Type Format (BTF)：<https://www.kernel.org/doc/html/latest/bpf/btf.html>

### 教程与博客
- eunomia-bpf 教程（本仓库参考来源）：<https://github.com/eunomia-bpf/bpf-developer-tutorial>
- Andrii Nakryiko 博客（libbpf 作者）：<https://nakryiko.com/>，尤其是 "BPF compile-once-run-everywhere" 系列
- xdp-tutorial：<https://github.com/xdp-project/xdp-tutorial>
- Cilium eBPF 文档：<https://docs.cilium.io/>

### 性能与分析
- Brendan Gregg 的 eBPF 工具集：<https://www.brendangregg.com/ebpf.html>
- 《BPF Performance Tools》

### 论文
- "The eBPF Perl of the Linux Kernel" / "BPF: A flexible kernel virtual machine"
- XDP 论文：<http://arthurchiao.art/blog/xdp-paper-acm-2018-zh/>

## 后续方向

本仓库之后的 lesson 19–21 展示了安全（LSM）、网络（tc）、高性能包处理（XDP）三个方向，可作为进一步深入各子系统的起点。
