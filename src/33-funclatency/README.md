# 33-funclatency — 函数延迟直方图

通用 kprobe+kretprobe 工具：入口记录时间戳，返回时计算延迟并按 log2 分桶。用户态用 bpf_program__attach_kprobe 指定目标函数名。

## 运行
```bash
make -C src/33-funclatency
sudo ./src/33-funclatency/funclatency vfs_read us
```
