# 69-freplace — BPF 程序运行时热补丁（freplace）

## 概述

用 `BPF_PROG_TYPE_EXT`（`SEC("freplace/...")`）在运行时替换另一个 BPF 程序中的函数——不是替换内核函数（那是 fentry/fexit），而是替换 **BPF-to-BPF** 的函数调用。

### 工作原理

```
┌─ 目标程序 (target.bpf.c) ────────────────────────────┐
│                                                       │
│  __noinline int filter_check(__u32 pid) {             │
│      return 1;  // 原始：记录所有进程                  │
│  }                                                    │
│                                                       │
│  SEC("tp/sched/sched_process_exec")                   │
│  int target_prog(void *ctx) {                         │
│      if (filter_check(pid))  ← 调用 filter_check     │
│          ringbuf_send(pid);                           │
│  }                                                    │
└──────────────────────────┬────────────────────────────┘
                           │ freplace 替换 filter_check()
                           ▼
┌─ 扩展程序 (ext.bpf.c) ──────────────────────────────┐
│                                                       │
│  SEC("freplace/filter_check")                          │
│  int filter_check(__u32 pid) {                         │
│      return (pid % 2) == 0;  // 新：只记录偶数 PID    │
│  }                                                    │
│                                                       │
│  加载时设置 attach_prog_fd = target prog fd           │
│  bpf_program__attach_freplace(prog, target_fd, ...)   │
└───────────────────────────────────────────────────────┘
```

### 关键：防止 filter_check 被内联

BPF 的 `clang -target bpf` 默认在 `-O2` 下内联所有函数。freplace 要求被替换的函数作为**独立 subprogram** 存在（指令流中有 `call filter_check`）。

解决方案：
- `__attribute__((noinline))` + `volatile` 局部变量（防止简单函数被内联）
- 编译 target 时添加 `-mllvm -inline-threshold=0`（强制禁用内联优化）

### freplace vs fentry/fexit

| 维度 | fentry/fexit | freplace (EXT) |
|---|---|---|
| 替换目标 | **内核函数** | **BPF 程序中的函数** |
| BTF 来源 | vmlinux BTF | 目标 BPF 程序的 BTF |
| attach 参数 | 内核函数 BTF ID | `attach_prog_fd` + 函数名 |
| 影响 | 所有调用该内核函数的代码 | 仅目标 BPF 程序的调用 |
| 替换 vs 观察 | 观察（不改变函数行为） | **替换**（完全改变函数行为） |

## 编译与运行

```bash
make -C src/69-freplace

# 终端 1：启动 target
sudo ./src/69-freplace/target
# 输出：所有 exec 事件（filter_check 返回 1=记录）

# 终端 2：attach ext（替换 filter_check）
sudo ./src/69-freplace/ext <target_prog_id>
# target 输出变化：奇数 PID 被 [FILTERED]，偶数 PID 仍 [EXEC]

# 终端 2：Ctrl-C detach ext
# target 恢复：再次记录所有 exec 事件
```

## 输出示例

```
# attach 前：所有 exec 事件
[EXEC]     pid=329306 comm=grep
[EXEC]     pid=329307 comm=head

# attach 后：奇数 PID 被过滤
[FILTERED] pid=329315 comm=ls
[EXEC]     pid=329316 comm=cat
[FILTERED] pid=329317 comm=sleep

# detach 后：恢复记录所有
[EXEC]     pid=329319 comm=ls
```

## 文件结构

```
69-freplace/
├── Makefile              # 双二进制（target 需特殊编译选项）
├── README.md
├── freplace.h            # 共享：事件结构体
├── target.bpf.c          # 目标程序：filter_check() + exec 追踪
├── target.c              # 目标用户态：加载 + ringbuf 轮询
├── ext.bpf.c             # 扩展程序：freplace/filter_check
└── ext.c                 # 扩展用户态：加载 ext + attach 到 target
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `BPF_PROG_TYPE_EXT` | 替换另一个 BPF 程序中的函数 |
| `SEC("freplace/func")` | 声明替换目标程序中的 `func` 函数 |
| `bpf_program__set_attach_target` | 设置 attach 目标（target prog fd） |
| `bpf_program__attach_freplace` | 创建 freplace link |
| `bpf_prog_get_fd_by_id` | 通过 prog ID 获取 fd（跨进程） |
| `__attribute__((noinline))` + `volatile` | 防止 BPF 函数被内联 |
| `-mllvm -inline-threshold=0` | 编译选项：强制禁用内联 |
| `bpf_link__destroy` | detach freplace，target 恢复原始逻辑 |
| 双 skeleton 设计 | target 和 ext 各自独立 skeleton，ext 需要 target 的 fd |

## 真实场景

| 场景 | 描述 |
|---|---|
| **运行时 BPF 程序补丁** | 不重新加载整个 BPF 程序，只替换其中一个函数 |
| **策略热切换** | 同一 BPF 程序，通过 attach/detach freplace 动态切换行为 |
| **测试/调试** | 替换 BPF 程序中的函数来测试不同逻辑 |
| **Cilium** | 用于策略更新，动态替换 BPF 程序中的过滤逻辑 |
