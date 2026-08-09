# 74-uprobe-multi-session

用三种 uprobe SEC 类型监控用户态函数，对比 `uprobe.multi`、`uretprobe.multi`、`uprobe.session` 的差异。

## 三种 SEC 类型对比

| SEC 名称 | attach_type | 运行时机 | 一个程序监控多个函数 | 入口+返回一体 |
|----------|------------|---------|-------------------|-------------|
| `uprobe.multi` | `BPF_TRACE_UPROBE_MULTI` | 函数入口 | ✅（cookie 区分） | ❌ |
| `uretprobe.multi` | `BPF_TRACE_UPROBE_MULTI` (retprobe) | 函数返回 | ✅（cookie 区分） | ❌ |
| `uprobe.session` | `BPF_TRACE_UPROBE_SESSION` | 入口 + 返回 | ❌（单函数） | ✅（session cookie） |

### 与传统 uprobe 的对比

| 维度 | 传统 `uprobe`/`uretprobe` | `uprobe.multi` | `uprobe.session` |
|------|--------------------------|---------------|-----------------|
| 程序数（N 个函数） | N 个程序 | **1 个程序** | 1 个程序 |
| 区分函数 | 无法 | **cookie** | — |
| 入口+返回延迟 | 2 程序 + hash map 传数据 | 2 程序 + hash map | **1 程序 + session cookie** |
| attach API | `bpf_program__attach_uprobe` | `bpf_program__attach_uprobe_multi` | `bpf_program__attach_uprobe_multi` (session=true) |

## 做什么

本示例是**自包含**的：目标函数 `work_a`、`work_b`、`work_c` 定义在用户态加载器中，BPF 程序 attach 到自身进程 (pid=0)。

- **`uprobe.multi`**：一个 BPF 程序 attach 到 `work_a` + `work_b` 入口，通过 cookie (FUNC_A=1, FUNC_B=2) 区分是哪个函数，读取函数参数
- **`uretprobe.multi`**：同一个 BPF 程序 attach 到 `work_a` + `work_b` 返回，同样用 cookie 区分
- **`uprobe.session`**：一个 BPF 程序 attach 到 `work_c`，入口存时间戳到 session cookie，返回时计算延迟

## 运行

```bash
make -C src/74-uprobe-multi-session
sudo ./src/74-uprobe-multi-session/uprobe-multi-session
```

### 输出示例

```
Attached:
  uprobe.multi    → work_a, work_b (entry,  with cookies)
  uretprobe.multi → work_a, work_b (return,with cookies)
  uprobe.session  → work_c (entry + return)

Calling work_a/work_b/work_c 5 times...

[ENTRY  ] func=work_a arg=0  pid=12345
[RETURN ] func=work_a  pid=12345
[ENTRY  ] func=work_b arg=0  pid=12345
[RETURN ] func=work_b  pid=12345
[SESSION] func=work_c  latency=3066 us  pid=12345
[ENTRY  ] func=work_a arg=1  pid=12345
[RETURN ] func=work_a  pid=12345
[ENTRY  ] func=work_b arg=1  pid=12345
[RETURN ] func=work_b  pid=12345
[SESSION] func=work_c  latency=3068 us  pid=12345
...
```

## 教学概念

| 概念 | 说明 |
|------|------|
| `SEC("uprobe.multi")` | 多函数入口 uprobe，attach_type=BPF_TRACE_UPROBE_MULTI |
| `SEC("uretprobe.multi")` | 多函数返回 uprobe，retprobe=true |
| `SEC("uprobe.session")` | 入口+返回一体 uprobe，attach_type=BPF_TRACE_UPROBE_SESSION |
| `bpf_program__attach_uprobe_multi()` | libbpf 手动 attach API，支持 syms/cookies/session/retprobe 选项 |
| `bpf_get_attach_cookie(ctx)` | 在 BPF 中读取 attach 时设置的 cookie，区分多个 attach 点 |
| `bpf_session_is_return(ctx)` | uprobe.session 专用：判断当前是入口还是返回阶段 |
| `bpf_session_cookie(ctx)` | uprobe.session 专用：获取 session cookie 指针，入口存/返回取 |
| `__attribute__((noinline))` | 防止编译器内联目标函数，保留符号可被 uprobe attach |
| pid=0 | attach 到自身进程，适用于自包含示例 |

## 技术细节

### Cookie 机制

`bpf_program__attach_uprobe_multi()` 的 `opts.cookies` 数组为每个函数分配一个 64 位 cookie。BPF 程序通过 `bpf_get_attach_cookie(ctx)` 读取当前触发 uprobe 的 cookie 值：

```c
/* 用户态：设置 cookie */
const char *syms[] = { "work_a", "work_b" };
__u64 cookies[] = { FUNC_A, FUNC_B };  /* 1, 2 */
opts.syms = syms;
opts.cookies = cookies;
opts.cnt = 2;

/* 内核态：读取 cookie */
__u64 cookie = bpf_get_attach_cookie(ctx);
if (cookie == FUNC_A) { /* work_a triggered */ }
```

### uprobe.session vs 传统 uprobe+uretprobe

测量函数延迟时：

**传统方案**（2 个 BPF 程序 + hash map）：
```
uprobe   → 程序 A：bpf_ktime_get_ns() → 存入 map[tid]
uretprobe → 程序 B：从 map[tid] 读时间戳 → 计算延迟
```

**uprobe.session**（1 个 BPF 程序 + session cookie）：
```
uprobe.session → 程序 C：
  入口: bpf_session_is_return()=false → *cookie = bpf_ktime_get_ns()
  返回: bpf_session_is_return()=true  → delta = now - *cookie
```

session cookie 是**内核内置的 per-call 私有存储**，无需用户创建 map，无需按 tid 索引。

### 自包含 attach (pid=0)

`bpf_program__attach_uprobe_multi(prog, 0, binary_path, ...)` 中 `pid=0` 表示 attach 到自身进程。目标函数 `work_a/b/c` 定义在加载器中，通过 `readlink("/proc/self/exe")` 获取自身路径。`pid=-1` 则监控所有进程。

### 为什么需要 noinline

`common.mk` 中用户态程序用 `-g -Wall` 编译（无 `-O2`），但编译器仍可能内联 static 函数。`__attribute__((noinline))` 确保函数有独立的符号表入口，uprobe 才能通过符号名找到地址。

## 文件结构

```
74-uprobe-multi-session/
├── Makefile                       # APP := uprobe-multi-session
├── uprobe-multi-session.h          # 共享：event 结构、cookie 常量
├── uprobe-multi-session.bpf.c      # 3 个 BPF 程序
├── uprobe-multi-session.c          # 加载器 + 目标函数 + ringbuf 消费
└── README.md
```
