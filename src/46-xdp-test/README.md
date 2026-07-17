# 46-xdp-test — XDP 包计数/打流

在 XDP hook 计数经过的包（per-cpu array），周期性输出总包数，用于测量 XDP 吞吐。

## 运行
```bash
make -C src/46-xdp-test
sudo ./src/46-xdp-test/xdp-test lo 2
```
