# 6-sigsnoop

捕获信号发送（`kill` / `tkill` / `tgkill`），用哈希表保存状态。

## 做什么

- 内核态：
  - 在 `sys_enter_{kill,tkill,tgkill}` 上捕获目标 pid 与信号，存入哈希表（键为发送者 `pid_tgid`）；
  - 在 `sys_exit_{kill,tkill,tgkill}` 上查表，把结果（成功/失败、返回值）发送到 ring buffer；
  - 全局变量 `target_sig` 可按信号号过滤。
- 用户态：argp 解析 `--signal`，轮询 ring buffer。

## 教学概念

- 哈希表在 enter/exit 之间保存状态。
- 多个 tracepoint 挂载点 + `__always_inline` 共享逻辑。
- 三种 kill 系统调用参数布局的差异（`kill(pid,sig)` / `tkill(tid,sig)` / `tgkill(tgid,tid,sig)`）。

## 运行

```bash
make -C src/6-sigsnoop
sudo ./src/6-sigsnoop/sigsnoop                 # 追踪所有信号
sudo ./src/6-sigsnoop/sigsnoop --signal 9       # 只看 SIGKILL
```
