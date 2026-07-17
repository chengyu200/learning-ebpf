# 27-replace — 透明替换文件读取内容

在 sys_exit_read 遍历返回缓冲区，用 bpf_probe_write_user 将所有 'from' 子串原地替换为 'to'（必须等长）。

## 运行
```bash
make -C src/27-replace
echo 'hello world' > /tmp/t; sudo ./src/27-replace/replace world eBPF & cat /tmp/t
```
