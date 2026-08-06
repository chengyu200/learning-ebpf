# 72-ksyscall — 跨架构系统调用追踪（ksyscall + kretsyscall）

## 概述

用 `SEC("ksyscall/openat")` 和 `SEC("kretsyscall/openat")` 追踪 `openat` 系统调用的完整生命周期：入口获取参数（文件名 + flags），返回获取返回值（fd 或错误码）+ 延迟。

### ksyscall 的核心价值：跨架构兼容

```c
// 传统做法：手动写架构名，换 CPU 架构就坏
SEC("kprobe/__arm64_sys_openat")   // 只在 aarch64
SEC("kprobe/__x64_sys_openat")      // 只在 x86_64

// ksyscall 做法：架构无关
SEC("ksyscall/openat")              // libbpf 自动解析
SEC("kretsyscall/openat")           // 返回探针，同样自动解析
```

libbpf 的 `attach_ksyscall` 内部：
1. 检测 `FEAT_SYSCALL_WRAPPER`（内核是否使用架构前缀的 syscall wrapper）
2. 若支持：函数名 = `__arm64_sys_openat`（aarch64）/ `__x64_sys_openat`（x86_64）
3. 若不支持：函数名 = `__se_sys_openat`
4. 用 `bpf_program__attach_kprobe_opts` 挂载 kprobe/kretprobe

### 两个探针配合

| SEC | 触发时机 | 获取内容 | BPF 宏 |
|---|---|---|---|
| `ksyscall/openat` | 系统调用入口 | dfd, filename, flags | `BPF_KPROBE` |
| `kretsyscall/openat` | 系统调用返回 | ret（fd 或错误码） | `BPF_KRETPROBE` |

通过 HASH map（key=pid）在入口和返回之间传递时间戳，计算 syscall 延迟。

## 编译与运行

```bash
make -C src/72-ksyscall
sudo ./src/72-ksyscall/ksyscall

# 另开终端测试
cat /etc/passwd          # openat SUCCESS (ret=fd)
cat /nonexistent          # openat FAILED (ret=-ENOENT)
```

## 输出示例

```
ksyscall: tracing openat (entry + exit). Ctrl-C to stop.
Test: cat /etc/passwd  (success)  |  cat /nonexistent  (fail)

[ENTRY] pid=1234   comm=cat          openat("/etc/passwd", flags=0x0)
[EXIT]  pid=1234   comm=cat          openat ret=3 (fd)      latency=1284 ns
[ENTRY] pid=1235   comm=cat          openat("/nonexistent", flags=0x0)
[EXIT]  pid=1235   comm=cat          openat ret=-2 (No such file or directory)  latency=856 ns

=== Summary ===
  Entry events:  2
  Exit events:   2
  Success (fd):  1
  Failed:        1
```

## 文件结构

```
72-ksyscall/
├── Makefile
├── README.md
├── ksyscall.h              # 共享：事件结构体
├── ksyscall.bpf.c          # ksyscall/openat + kretsyscall/openat + HASH map
└── ksyscall.c              # 用户态：ringbuf 轮询 + 统计
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `SEC("ksyscall/<name>")` | 跨架构系统调用入口探针 |
| `SEC("kretsyscall/<name>")` | 跨架构系统调用返回探针 |
| `BPF_KPROBE` | kprobe 的类型化参数宏（ksyscall 也用此宏） |
| `BPF_KRETPROBE` | kretprobe 的返回值宏（kretsyscall 也用此宏） |
| `FEAT_SYSCALL_WRAPPER` | 内核是否使用 `__arch_sys_<name>` 命名 |
| `arch_specific_syscall_pfx()` | libbpf 获取架构前缀（arm64/x64/...） |
| HASH map 传递 entry→exit | 按 pid 存时间戳，返回时计算延迟 |

## 与其他示例的对比

| 示例 | 挂载方式 | 跨架构 | 返回值 | 延迟 |
|---|---|---|---|---|
| 2-kprobe-unlink | `kprobe/vfs_unlink` | ✅（内核函数名跨架构） | ❌ | ❌ |
| 34-syscall | `kprobe/__arm64_sys_openat` + `tp/syscalls` | ❌ | ❌ | ❌ |
| **72-ksyscall** | **`ksyscall/openat` + `kretsyscall/openat`** | **✅** | **✅** | **✅** |

## 真实场景

| 场景 | 描述 |
|---|---|
| **跨架构追踪工具** | 同一源码在 x86/arm64/riscv 上都能运行 |
| **系统调用延迟分析** | ksyscall 记录时间戳，kretsyscall 计算 delta |
| **安全审计** | 监控特定系统调用的调用者、参数和结果 |
| **故障排查** | 捕获系统调用失败（ENOENT/EACCES/...）的详细信息 |
