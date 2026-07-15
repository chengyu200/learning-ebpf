# 3-fentry-unlink

用 **fentry**（BTF-based）监控文件删除，与 [2-kprobe-unlink](../2-kprobe-unlink) 对照。

## 做什么

- 内核态：在 `vfs_unlink` 上挂 fentry，功能与示例 2 相同。
- 用户态：同示例 2。

## 教学概念

- fentry/fexit 挂载点 `SEC("fentry/...")` 与 `BPF_PROG` 宏。
- 与 kprobe 的对比：
  - fentry 基于 BTF，参数**类型化**、可直接按名引用，无需从寄存器手动解析；
  - fentry 性能开销更低（基于函数跳转而非断点）；
  - fentry 要求内核开启 BTF（`CONFIG_DEBUG_INFO_BTF`）。

## 运行

```bash
make -C src/3-fentry-unlink
sudo ./src/3-fentry-unlink/fentry-unlink
# 另开终端：rm /tmp/foo
```

## 适配说明

与示例 2 一样改挂 `vfs_unlink`（本机内核无 `do_unlinkat` 导出符号）。
