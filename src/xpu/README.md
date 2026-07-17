# xpu — GPU/NPU 追踪

本目录对应原教程中 GPU/NPU 相关的进阶示例（flamegraph、gpu-kernel-driver、npu-kernel-driver）。

## 为什么本机无法运行

本机无 GPU（NVIDIA）和 NPU（Intel NPU）硬件设备。

## 包含的示例

- **xpu/flamegraph**：用 CUPTI 构建 GPU 火焰图分析器
- **xpu/gpu-kernel-driver**：通过内核 tracepoint 监控 GPU 驱动活动
- **xpu/npu-kernel-driver**：追踪 Intel NPU 内核驱动操作

## 参考

- 原教程：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/xpu>
