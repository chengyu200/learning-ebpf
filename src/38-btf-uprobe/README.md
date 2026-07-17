# 38-btf-uprobe — CO-RE 扩展到用户态

uprobe 挂 libc malloc，演示 BPF_CORE_READ/CO-RE 对用户态类型的适用性（libc 无 BTF 时回退到直接读取）。

## 运行
```bash
make -C src/38-btf-uprobe
sudo ./src/38-btf-uprobe/btf-uprobe
```
