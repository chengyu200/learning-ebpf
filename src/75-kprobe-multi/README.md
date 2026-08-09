# 75-kprobe-multi — 多函数 kprobe 追踪

## 概述

用 `kprobe.multi`、`kretprobe.multi` 和 `kprobe.session` 一次追踪多个 VFS 函数的入口、返回和延迟。三个程序覆盖传统 kprobe 需要数十个程序才能完成的工作。

### 三种 SEC

| SEC | 触发时机 | 独特能力 |
|---|---|---|
| `kprobe.multi/vfs_*` | **多个函数**入口 | 一次 attach 到所有 `vfs_*` 函数（~70 个） |
| `kretprobe.multi/vfs_*` | **多个函数**返回 | 同上，返回探针 |
| `kprobe.session/vfs_read` | 入口**+**返回 | 一个程序同时处理入口和返回，测量延迟 |

### 与传统 kprobe 的对比

```c
// 传统：每个函数一个程序
SEC("kprobe/vfs_read")      // 程序 1
SEC("kprobe/vfs_write")     // 程序 2
SEC("kprobe/vfs_unlink")     // 程序 3
// 70 个 vfs_* 函数 → 70 个程序 + 70 条 link

// kprobe.multi：一个程序匹配所有
SEC("kprobe.multi/vfs_*")    // 1 个程序 + 1 条 link（内部 attach 70 个函数）
```

### kprobe.session vs fsession（64-fsession）

| 维度 | fsession | kprobe.session |
|---|---|---|
| 底层 | fentry/fexit trampoline | kprobe int3 |
| BTF 依赖 | ✅ 需要 | ❌ 不需要 |
| 函数限制 | 仅 BTF 导出函数 | 任意内核函数 |
| 延迟测量 | `bpf_session_is_return()` + `bpf_session_cookie()` | 同 |
| **返回值语义** | **入口 非`0`=继续返回, `0`=跳过** | **入口 `0`=继续返回, 非`0`=跳过（相反！）** |

## 编译与运行

```bash
make -C src/75-kprobe-multi

# 推荐：带 PID 参数，只追踪指定进程（避免后台进程刷屏）
# 另开终端执行 cat /etc/passwd 等，获取其 PID
sudo ./src/75-kprobe-multi/kpmulti <pid>

# 不带参数：追踪所有进程（排除自身，输出较多）
sudo ./src/75-kprobe-multi/kpmulti
```

### 测试方法

```bash
# 终端 1：启动追踪
sudo ./src/75-kprobe-multi/kpmulti

# 终端 2：获取 PID 并触发 VFS 操作
echo $$
cat /etc/passwd          # 触发 vfs_read
echo "x" > /tmp/test     # 触发 vfs_write
rm /tmp/test             # 触发 vfs_unlink

# 终端 1 中 Ctrl-C 查看统计
```

### 带 PID 过滤（推荐）

`vfs_*` 函数被系统所有进程频繁调用（sshd、sudo、systemd 等），不带过滤会刷屏。带 PID 参数只追踪指定进程：

```bash
# 终端 1：先获取目标进程 PID
bash -c 'echo "my pid=$$" && sleep 30 && cat /etc/passwd'

# 终端 2：用该 PID 启动追踪
sudo ./src/75-kprobe-multi/kpmulti <pid>
```

## 输出示例

```
Loaded 88543 kernel symbols
kprobe.multi: tracing vfs_* (entry + return + session).
  Filtering: only pid=86944
Test: cat /etc/passwd  |  rm /tmp/test  |  echo > /tmp/x
Ctrl-C to stop.

[ENTRY]   pid=86944  comm=bash         func=vfs_fstatat
[ENTRY]   pid=86944  comm=bash         func=vfs_statx
[ENTRY]   pid=86944  comm=bash         func=vfs_getattr_nosec
[RETURN]  pid=86944  comm=bash         func=vfs_getattr_nosec
[RETURN]  pid=86944  comm=bash         func=vfs_statx
[RETURN]  pid=86944  comm=bash         func=vfs_fstatat
[ENTRY]   pid=86944  comm=bash         func=vfs_open
[RETURN]  pid=86944  comm=bash         func=vfs_open
[ENTRY]   pid=86944  comm=bash         func=vfs_write
[RETURN]  pid=86944  comm=bash         func=vfs_write
[LATENCY] pid=86944  comm=bash         func=vfs_read             latency=15234 ns

=== Summary ===
Function                          Entry   Return  Avg Latency
----------                        -----   ------  -----------
vfs_fstatat                          22       22            -
vfs_statx                            22       22            -
vfs_getattr_nosec                     9        9            -
vfs_open                              1        1            -
vfs_write                             1        1            -
vfs_read                              8        8     12345 ns
```

## 文件结构

```
75-kprobe-multi/
├── Makefile
├── README.md
├── kpmulti.h              # 共享事件结构体
├── kpmulti.bpf.c          # 3 个程序：kprobe.multi + kretprobe.multi + kprobe.session
└── kpmulti.c              # 用户态：kallsyms 解析 + ringbuf 轮询 + PID 过滤 + 统计
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `SEC("kprobe.multi/vfs_*")` | 通配符匹配多个内核函数 |
| `SEC("kretprobe.multi/vfs_*")` | 同上，返回探针 |
| `SEC("kprobe.session/vfs_read")` | 入口+返回合一 |
| `bpf_get_func_ip(ctx)` | 获取被探测函数地址 |
| `bpf_session_is_return()` | 区分入口/返回阶段 |
| `bpf_session_cookie()` | per-call 私有存储（存时间戳） |
| `/proc/kallsyms` | 用户态 IP→函数名解析 |
| `bpf_kprobe_multi_opts` | libbpf 选项（.retprobe / .session） |
| `const volatile target_pid` | BPF rodata PID 过滤（load 前设置） |
| kprobe.session 返回值 | 入口 `0`=继续返回, 非`0`=跳过（与 fsession 相反） |

## 与现有示例的关系

| 示例 | 技术 | 函数数 | 程序数 | 返回值 | 延迟 |
|---|---|---|---|---|---|
| 2-kprobe-unlink | kprobe | 1 | 1 | ❌ | ❌ |
| 33-funclatency | kprobe+kretprobe | 1 | 2 | ❌ | ✅ |
| 64-fsession | fsession | 1 | 1 | ✅ | ✅ |
| **75-kprobe-multi** | **multi + session** | **70+** | **3** | **✅** | **✅** |
