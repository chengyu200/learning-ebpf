# 26-sudo — 检测 passwd 风格文件读取

追踪目标进程的 read 调用，检测返回缓冲区中的 ':x:' 模式（passwd 文件特征）。演示 BPF 对用户态缓冲区的读取与安全检测。

## 运行
```bash
make -C src/26-sudo
sudo ./src/26-sudo/sudo --pid <PID>
```
