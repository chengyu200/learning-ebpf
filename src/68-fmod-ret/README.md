# 68-fmod-ret

用 `BPF_MODIFY_RETURN`（`fmod_ret`）向 `read()` 系统调用注入错误返回值，演示错误注入技术。

## 什么是 fmod_ret

`BPF_MODIFY_RETURN` 是 `BPF_PROG_TYPE_TRACING` 的一个 attach 类型，通过 `SEC("fmod_ret/function")` 挂载。它在**原始函数执行之前**运行，可以**决定是否跳过原始函数**并覆盖返回值。

### Trampoline 执行顺序

```
fentry（观察参数，不能阻止）
       ↓
fmod_ret（决定是否执行原始函数）  ← 这里
  返回 0  → 原始函数正常执行
  返回非0 → 跳过原始函数，返回值 = fmod_ret 的返回值
       ↓
原始函数执行（如果 fmod_ret 返回 0）
       ↓
fexit（观察参数 + 返回值）
```

### 与 fentry/fexit/bpf_override_return 的对比

| 特性 | fentry | fexit | **fmod_ret** | bpf_override_return |
|------|--------|-------|-------------|---------------------|
| 挂载类型 | TRACING | TRACING | **TRACING** | KPROBE |
| 执行时机 | 函数入口 | 函数出口 | **函数入口（函数执行前）** | 函数入口 |
| 能否阻止执行 | ❌ | ❌ | **✅ 返回非0 跳过** | ✅ |
| 能否读返回值 | ❌ | ✅ | ❌（函数还没执行） | ❌ |
| 需要 BTF | ✅ | ✅ | **✅** | ❌ |
| 需要特殊 CONFIG | 无 | 无 | **CONFIG_FUNCTION_ERROR_INJECTION** | CONFIG_BPF_KPROBE_OVERRIDE |
| 目标函数限制 | 任意有 BTF 的函数 | 任意有 BTF 的函数 | **仅 ALLOW_ERROR_INJECTION 标记的函数** | 任意 kprobe |
| 性能 | 高（trampoline） | 高 | **高（trampoline）** | 中（int3 断点） |

## 主要使用场景

1. **错误注入测试**：让 `read()` 返回 `-ENOMEM`，测试应用的容错能力
2. **安全策略**：阻止特定进程执行某些操作（如 `clone`、`mmap`）
3. **故障模拟**：模拟硬件故障、资源耗尽等场景
4. **替代 bpf_override_return**：更现代的 trampoline 方式，性能更高

## 用法

```bash
make -C src/68-fmod-ret

# 对特定 PID 注入 -ENOMEM（-12）— --pid 是必填参数
sudo ./src/68-fmod-ret/fmod-ret --pid <PID> --errno -12

# 对特定 PID 注入 -EPERM（-1）
sudo ./src/68-fmod-ret/fmod-ret --pid <PID> --errno -1

# 对所有进程注入（危险！需要明确传 --pid 0）
sudo ./src/68-fmod-ret/fmod-ret --pid 0 --errno -12
```

参数：
- `--pid <PID>`：**必填**。目标进程 PID（0 = 所有进程，危险！）
- `--errno <N>`：注入的错误码（默认 -12 = ENOMEM）
  - `-1` = EPERM（操作不允许）
  - `-5` = EIO（输入输出错误）
  - `-12` = ENOMEM（内存不足）
  - `-13` = EACCES（权限不足）
- `Ctrl-C` 停止注入

> 不传 `--pid` 会报错退出，避免误操作对所有进程注入错误。

## 验证

```bash
# 终端 1：启动一个持续调用 read() 的进程
dd if=/dev/zero of=/dev/null bs=4096 count=10000000 &
DD_PID=$!

# 终端 2：对 dd 注入 -ENOMEM
sudo ./src/68-fmod-ret/fmod-ret --pid $DD_PID --errno -12

# 终端 1 或 3：查看 trace_pipe
sudo cat /sys/kernel/tracing/trace_pipe | head -5
```

### 验证结果

trace_pipe 输出（注入 -ENOMEM）：
```
dd-319592  [001] ...11 741864.839483: bpf_trace_printk: fmod_ret: inject errno -12 to pid 319592 (dd)
dd-319592  [001] ...11 741864.839483: bpf_trace_printk: fmod_ret: inject errno -12 to pid 319592 (dd)
dd-319592  [001] ...11 741864.839484: bpf_trace_printk: fmod_ret: inject errno -12 to pid 319592 (dd)
...
```

trace_pipe 输出（注入 -EPERM）：
```
dd-319643  [001] ...11 741903.774251: bpf_trace_printk: fmod_ret: inject errno -1 to pid 319643 (dd)
dd-319643  [001] ...11 741903.774251: bpf_trace_printk: fmod_ret: inject errno -1 to pid 319643 (dd)
...
```

> 注意：`cat` 使用 `sendfile()` 而非 `read()`，不会触发注入。用 `dd` 或其他直接调用 `read()` 的程序测试。

## 可注入的函数

`fmod_ret` 只能挂载到内核中标记了 `ALLOW_ERROR_INJECTION` 的函数。本机有 530 个可用函数：

```bash
# 查看可注入函数列表
cat /sys/kernel/debug/error_injection/list | head -10
# __arm64_sys_read       ERRNO
# __arm64_sys_write      ERRNO
# __arm64_sys_clone      ERRNO
# __arm64_sys_mmap       ERRNO
# __arm64_sys_unshare    ERRNO
# ...

# 统计数量
cat /sys/kernel/debug/error_injection/list | wc -l
# 530
```

## 与 lesson 34-syscall 的对比

lesson 34 用 `bpf_override_return`（kprobe 方式）实现 syscall 拦截，本示例用 `fmod_ret`（tracing 方式）：

| 特性 | 34-syscall (bpf_override_return) | **68-fmod-ret** |
|------|------|------|
| 挂载类型 | kprobe | **fmod_ret (tracing)** |
| 底层机制 | int3 断点 | **trampoline** |
| 需要 BTF | 否 | **是** |
| 需要 CONFIG | BPF_KPROBE_OVERRIDE | **FUNCTION_ERROR_INJECTION** |
| 目标函数限制 | 任意 kprobe | **仅 ALLOW_ERROR_INJECTION 函数** |
| 性能 | 中 | **高** |
| 代码复杂度 | 中（手动 attach kprobe） | **低（libbpf 自动 attach）** |
