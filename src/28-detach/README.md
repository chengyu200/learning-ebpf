# 28-detach — eBPF 程序生命周期：detach 后继续运行

演示 pinning：attach 子命令加载+pin link/map 后退出，程序继续运行；status 读取计数；clean 卸载。

## 运行
```bash
make -C src/28-detach
sudo ./src/28-detach/detach attach; sudo ./src/28-detach/detach status; sudo ./src/28-detach/detach clean
```
