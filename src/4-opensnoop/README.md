# 4-opensnoop

追踪 `openat()` 系统调用，支持全局变量过滤。

## 做什么

- 内核态：
  - `sys_enter_openat`：读取用户态文件名指针（`args[1]`）并存入哈希表（键为 `pid_tgid`）；
  - `sys_exit_openat`：查表取出文件名，连同返回值（fd 或 `-errno`）发送到 ring buffer；
  - 全局变量 `target_pid` / `failed_only` 实现按 PID / 仅失败 过滤。
- 用户态：用 argp 解析命令行参数，在 load 前设置 rodata 全局变量，轮询 ring buffer。

## 教学概念

- **全局变量**（`const volatile`）作为 BPF 配置：编译进 `.rodata`，用户态在 load 前通过 `skel->rodata` 写入。
- enter/exit 配对用**哈希表**携带中间状态（文件名）。
- `bpf_probe_read_user_str` 读取用户态字符串。

## 运行

```bash
make -C src/4-opensnoop
sudo ./src/4-opensnoop/opensnoop                 # 追踪所有 openat
sudo ./src/4-opensnoop/opensnoop --failed        # 只看失败
sudo ./src/4-opensnoop/opensnoop --pid 1234      # 只看某进程
```
