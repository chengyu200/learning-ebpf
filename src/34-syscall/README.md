# 34-syscall — 检查/修改系统调用参数

sys_enter_openat tracepoint 检查 filename+flags 并打印；可选 kprobe override 用 bpf_override_return 拒绝调用（需 CONFIG_BPF_KPROBE_OVERRIDE）。

## 运行
```bash
make -C src/34-syscall
sudo ./src/34-syscall/syscall  # 或 --pid PID --override
```
