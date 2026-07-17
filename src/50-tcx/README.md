# 50-tcx — TCX 可组合流量控制

用 bpf_program__attach_tcx 将 tc 程序挂到网卡的 TCX ingress 点（自动组合，无需手动建 clsact qdisc），计数 IPv4 包。

## 运行
```bash
make -C src/50-tcx
sudo ./src/50-tcx/tcx lo 2
```
