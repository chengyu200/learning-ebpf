# 47-cuda-events

追踪 CUDA GPU 操作。

## 为什么本机无法运行

本机无 GPU 设备（无 `/dev/nvidia*`，无 `nvidia-smi`），无法运行 CUDA 程序。

## 原教程做什么

通过 uprobe 挂载 CUDA 运行时库（libcudart）的关键函数，追踪 GPU 内核启动、内存拷贝等事件。

## 参考

- 原教程：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/47-cuda-events>
