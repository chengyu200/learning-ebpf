# 25-signal — 用 bpf_send_signal 终止进程

在 sys_enter_execve tracepoint 检查可执行路径，若包含目标子串则调用 bpf_send_signal(SIGKILL) 终止该进程。

## 运行
```bash
make -C src/25-signal
sudo ./src/25-signal/signal dangerous  # 终止 exec 包含 'dangerous' 的进程
```
