# 22-android

在 Android 上使用 eBPF 程序。

## 为什么本机无法运行

本机为 aarch64 Linux 桌面/服务器环境，非 Android。Android 上的 eBPF 需要 Android 内核（CONFIG_BPF + 特定 selinux 策略）及 `bpfloader`。

## 原教程做什么

在 Android 上加载 eBPF 程序，追踪网络/系统行为，通过 `bpfloader` 在开机时加载 `.o` 文件。

## 参考

- 原教程：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/22-android>
- Android BPF 文档：<https://source.android.com/docs/core/architecture/kernel/bpf>
