# 2-kprobe-unlink

用 **kprobe** 监控文件删除。

## 做什么

- 内核态：在 `vfs_unlink` 上挂 kprobe，捕获被删除文件的路径（`dentry->d_name.name`），连同 pid/uid/comm 通过 ring buffer 发送到用户态。
- 用户态：轮询 ring buffer 并打印。

## 教学概念

- kprobe 挂载点 `SEC("kprobe/...")` 与 `BPF_KPROBE` 宏。
- 用 `BPF_CORE_READ` 读取嵌套内核结构体字段（`dentry->d_name.name`）。
- `BPF_MAP_TYPE_RINGBUF` + `bpf_ringbuf_reserve/submit`。

## 运行

```bash
make -C src/2-kprobe-unlink
sudo ./src/2-kprobe-unlink/kprobe-unlink
# 另开终端：rm /tmp/foo
```

## 与原教程的差异

原教程挂钩 `do_unlinkat`；该函数在本机内核已被内联移除，故改挂 `vfs_unlink`。详见与 [3-fentry-unlink](../3-fentry-unlink) 的对比。
