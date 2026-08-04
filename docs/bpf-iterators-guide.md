# BPF Iterators 学习资料

> 来源：[BPF Iterators 官方文档](https://origin.kernel.org/doc/html/latest/bpf/bpf_iterators.html)
>
> 基于官方文档的中文总结，涵盖概念原理、API 用法、学习路径和示例思路。

---

## 一、概述：两种 BPF Iterator

官方文档明确区分了两个概念，这是理解 BPF Iterator 的基础：

| 类型 | 全称 | 本质 | 使用场景 |
|---|---|---|---|
| **BPF Iterator 程序类型** | BPF iterator *program type* | 独立的 BPF 程序类型（`SEC("iter/...")`），attach 后由用户态 `read()` 触发，通过 `seq_file` 输出 | 生成可 `cat` 的伪文件，类似 `/proc` 但格式可定制 |
| **Open-coded Iterator** | Open-coded BPF iterators | 一组 kfunc（`bpf_iter_<type>_{new,next,destroy}`），在任意 BPF 程序类型中用 `bpf_for_each()` 循环 | 在 BPF 程序内部遍历内核数据结构，更灵活 |

**核心区别**：前者是"用户触发遍历 → BPF 输出到 seq_file"；后者是"BPF 程序内部自己遍历"。

---

## 二、BPF Iterator 程序类型详解

### 2.1 工作原理

```
用户态                          内核态
──────                          ──────
1. load BPF program
2. bpf_link_create()  ───→   创建 link
3. bpf_iter_create()  ───→   创建可读的 iter fd
4. read(iter_fd)      ───→   内核遍历每个对象，调用 BPF 程序
                        ←───  BPF 用 BPF_SEQ_PRINTF 输出到 seq_file
5. close(iter_fd)
```

### 2.2 关键 API

| 层 | API | 说明 |
|---|---|---|
| **内核侧** | `SEC("iter/task")` 等 | 声明 iterator 程序 |
| **内核侧** | `BPF_SEQ_PRINTF(seq, fmt, ...)` | 格式化输出到 seq_file |
| **内核侧** | `bpf_seq_write(seq, data, len)` | 二进制输出 |
| **用户态** | `bpf_program__attach_iter(prog, opts)` | 创建 iter link |
| **用户态** | `bpf_iter_create(link_fd)` | 从 link 创建可读 fd |
| **用户态** | `read(iter_fd, buf, len)` | 触发遍历 |
| **用户态** | `bpftool iter pin ./obj.o /sys/fs/bpf/xxx` | pin 到 bpffs，可 `cat` |

### 2.3 支持的迭代目标

通过 `SEC("iter/<target>")` 指定，上下文结构体为 `bpf_iter__<target>`：

| SEC 名 | 上下文结构体 | 遍历对象 |
|---|---|---|
| `iter/task` | `bpf_iter__task` | 所有进程/线程 |
| `iter/task_file` | `bpf_iter__task_file` | 所有进程打开的文件 |
| `iter/task_vma` | `bpf_iter__task_vma` | 所有进程的 VMA（虚拟内存区域） |
| `iter/tcp4` / `iter/tcp6` | `bpf_iter__tcp` | TCP 连接 |
| `iter/udp4` / `iter/udp6` | `bpf_iter__udp` | UDP 连接 |
| `iter/bpf_map` | `bpf_iter__bpf_map` | 所有 BPF map |
| `iter/bpf_map_elem` | `bpf_iter__bpf_map_elem` | 某个 map 的所有元素 |
| `iter/bpf_prog` | `bpf_iter__bpf_prog` | 所有 BPF 程序 |
| `iter/ipv6_route` | — | IPv6 路由表 |
| `iter/bpf_link` | — | 所有 BPF link |

### 2.4 参数化（过滤）

默认遍历系统全部对象，可通过 `bpf_iter_attach_opts` 过滤：

```c
LIBBPF_OPTS(bpf_iter_attach_opts, opts);
union bpf_iter_link_info linfo = {};
linfo.task.pid = getpid();    /* 仅遍历当前进程 */
opts.link_info = &linfo;
opts.link_info_len = sizeof(linfo);
link = bpf_program__attach_iter(prog, &opts);
```

- `linfo.task.pid`：仅遍历指定进程
- `linfo.task.tid`：仅遍历指定线程
- 不设置（NULL）：遍历全部

### 2.5 参数化的两种方式对比

| 方式 | 实现 | 优点 | 缺点 |
|---|---|---|---|
| **attach_opts**（内核侧过滤） | `linfo.task.pid = pid` | 内核只遍历目标对象，高效 | 仅支持 pid/tid 过滤 |
| **全局变量 + BPF 内 if** | `if (task->tgid != target_pid) return 0;` | 过滤条件灵活（可按 comm、cgroup 等） | 仍遍历全部对象，只是 BPF 内跳过 |

---

## 三、Open-coded Iterator 详解

### 3.1 kfunc 三元组

每种 open-coded iterator 由三个 kfunc 组成：

```
bpf_iter_<type>_new(it, ...)   ← 构造器，初始化栈上的迭代器状态
bpf_iter_<type>_next(it)       ← 获取下一个元素，返回指针；NULL 表示结束
bpf_iter_<type>_destroy(it)    ← 析构器，释放资源
```

状态结构体 `struct bpf_iter_<type>` 必须在 BPF 栈上，大小必须是 8 的倍数。

### 3.2 命名约定（内核强制）

| 方法 | 命名规则 | 参数 | 返回值 | KF 标志 |
|---|---|---|---|---|
| 构造器 | `bpf_iter_<type>_new` | 第一个参数为 `struct bpf_iter_<type> *`，其余任意 | 任意 | `KF_ITER_NEW` |
| next | `bpf_iter_<type>_next` | 仅 `struct bpf_iter_<type> *` | 指针（NULL 表示结束） | `KF_ITER_NEXT` + `KF_RET_NULL` |
| 析构器 | `bpf_iter_<type>_destroy` | 仅 `struct bpf_iter_<type> *` | `void` | `KF_ITER_DESTROY` |

### 3.3 契约

- **构造器**：即使参数无效也必须初始化状态，使后续 `next()` 返回 NULL（构造空迭代器）
- **next**：保证最终返回 NULL；一旦返回 NULL，后续调用继续返回 NULL
- **析构器**：总是被调用一次（即使构造器失败或 next 未返回任何元素）

### 3.4 bpf_for_each 宏

libbpf 提供 `bpf_for_each()` 宏简化使用：

```c
struct bpf_iter_num it;
int *val;

bpf_for_each(num, val, 0, 100) {
    /* val 指向 0..99 */
    bpf_printk("val = %d", *val);
}
/* 等价于：
 * bpf_iter_num_new(&it, 0, 100);
 * while ((val = bpf_iter_num_next(&it))) { ... }
 * bpf_iter_num_destroy(&it);
 */
```

`bpf_for_each` 利用 C99 for 循环变量声明 + GCC `__attribute__((cleanup))` 自动调用析构器。

### 3.5 验证器如何处理循环

验证器在 `bpf_iter_<type>_next` 调用处**分叉验证状态**：

1. **先模拟 NULL 返回**（循环结束）→ 必须能到达程序出口
2. **再模拟非 NULL 返回**（新元素）→ 要么到达出口，要么到达下一次 `next` 调用且状态等价

只要每次迭代不引入新的状态约束（状态等价），验证器认为循环安全（有限次迭代）。这与条件跳转的状态分叉类似。

### 3.6 已有的 open-coded iterator 类型

| 类型 | kfunc 前缀 | 遍历对象 |
|---|---|---|
| `num` | `bpf_iter_num_*` | 整数范围 `[start, end)` |
| `task` | `bpf_iter_task_*` | 所有进程 |
| `task_vma` | `bpf_iter_task_vma_*` | 进程的 VMA |
| `css` | `bpf_iter_css_*` | cgroup 子系统状态 |
| `css_task` | `bpf_iter_css_task_*` | cgroup 内的任务 |

---

## 四、动机：为什么需要 BPF Iterator

| 传统方案 | 问题 | BPF Iterator 解决方案 |
|---|---|---|
| `/proc/net/tcp` 等 | 格式固定，改格式需 patch 内核 | BPF 程序自定义输出格式 |
| `ss` 等工具 | 新字段需内核 patch | BPF 程序直接读内核结构体 |
| `drgn` | 性能差（不能内核内指针追踪），可能读无效指针 | BPF 在内核内运行，安全高效 |

核心价值：**灵活性** — 用户自定义遍历哪些对象、读取哪些字段、以什么格式输出。

---

## 五、内核实现视角

添加新的 BPF iterator 程序类型需要注册 `struct bpf_iter_reg`：

```c
struct bpf_iter_reg {
    const char *target;                    // 迭代器名称，如 "task_file"
    bpf_iter_attach_target_t attach_target; // link_create 时的定制处理
    bpf_iter_detach_target_t detach_target;
    bpf_iter_show_fdinfo_t show_fdinfo;    // fdinfo 显示
    bpf_iter_fill_link_info_t fill_link_info;
    bpf_iter_get_func_proto_t get_func_proto; // iterator 专属 helper
    u32 ctx_arg_info_size;                 // 验证器参数信息
    struct bpf_ctx_arg_aux ctx_arg_info[BPF_ITER_CTX_ARG_MAX];
    u32 feature;                           // 如 BPF_ITER_RESCHED
    const struct bpf_iter_seq_info *seq_info; // seq_file 操作集
};
```

调用 `bpf_iter_reg_target()` 注册。参考 [task_vma iterator 实现补丁](https://lore.kernel.org/bpf/20210212183107.50963-2-songliubraving@fb.com/)。

---

## 六、仓库现有示例分析

仓库中 `src/features/bpf_iters/` 已有一个基础示例：

```c
// iters.bpf.c — 遍历所有 task，打印 pid/tid/comm
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task == NULL) return 0;
    BPF_SEQ_PRINTF(seq, "pid = %d tid=%d comm=%s\n",
                   task->tgid, task->pid, task->comm);
    return 0;
}
```

用户态流程：`open_and_load` → `attach_iter` → `bpf_iter_create` → `read` 循环。

**已覆盖**：
- `SEC("iter/task")` 基本用法
- `BPF_SEQ_PRINTF` 输出
- `bpf_program__attach_iter` + `bpf_iter_create` + `read` 流程

**未覆盖**：
- 参数化过滤（`bpf_iter_attach_opts`）
- pin 到 bpffs + `cat` 读取
- `iter/task_file` / `iter/task_vma` / `iter/tcp4` 等其他迭代目标
- open-coded iterator（`bpf_for_each`）
- 二进制输出（`bpf_seq_write`）

---

## 七、学习建议

### 学习路径

```
1. 理解概念（本文档）
   ↓
2. 运行现有示例 src/features/bpf_iters/
   ↓
3. 尝试不同 iter 目标（task_file, tcp4, bpf_map）
   ↓
4. 尝试参数化过滤（attach_opts + pid）
   ↓
5. 尝试 pin 到 bpffs + cat 读取
   ↓
6. 尝试 open-coded iterator（bpf_for_each + bpf_iter_num）
   ↓
7. 内核实现视角（bpf_iter_reg 结构体，阅读内核源码）
```

### 关键参考资料

| 资料 | 说明 |
|---|---|
| [官方文档](https://origin.kernel.org/doc/html/latest/bpf/bpf_iterators.html) | 本文档来源 |
| [内核 selftests](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/prog_tests/bpf_iter.c) | 最完整的使用示例 |
| [bpf_iter_task_file.c](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/progs/bpf_iter_task_file.c) | task_file iterator 程序 |
| [bpf_iter_tcp4.c](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/progs/bpf_iter_tcp4.c) | TCP iterator 程序 |
| [bpf_iter_task_vmas.c](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/progs/bpf_iter_task_vmas.c) | VMA iterator 程序 |
| [task_vma iterator 内核实现 patch](https://lore.kernel.org/bpf/20210212183107.50963-2-songliubraving@fb.com/) | 如何添加新 iterator 类型 |

### 易混淆点

1. **`bpf_iter_create` vs `bpf_link`**：link fd 不能直接 `read()`，必须用 `bpf_iter_create` 创建新的可读 fd
2. **`BPF_SEQ_PRINTF` vs `bpf_seq_write`**：前者格式化文本（可 `cat`），后者二进制（需用户态解析）
3. **程序类型 vs open-coded**：`SEC("iter/task")` 是程序类型；`bpf_for_each(task, ...)` 是 open-coded kfunc，可在任何 BPF 程序中使用
4. **参数化过滤的两种方式**：`attach_opts`（内核侧过滤，更高效）vs 全局变量在 BPF 程序内 `if` 过滤（更灵活但遍历全部对象）

---

## 八、示例程序思路

基于仓库现有基础和文档内容，以下是 5 个递进式示例思路：

### 思路 1：`iter/task_file` — 进程文件描述符审计（进阶版）

**目标**：遍历指定进程的所有打开文件，输出 tgid/pid/fd/file_ops

**教学点**：
- `SEC("iter/task_file")` + `bpf_iter__task_file` 上下文
- 参数化过滤（`linfo.task.pid = getpid()`）
- `BPF_SEQ_PRINTF` 格式化输出
- 对比现有 `features/bpf_iters`（task）扩展到 task_file

**BPF 侧**：
```c
SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx)
{
    if (ctx->task == NULL || ctx->file == NULL) return 0;
    BPF_SEQ_PRINTF(ctx->meta->seq, "%8d %8d %8d %lx\n",
                   ctx->task->tgid, ctx->task->pid,
                   ctx->fd, (long)ctx->file->f_op);
    return 0;
}
```

**用户态**：带 `bpf_iter_attach_opts` 的参数化 attach

### 思路 2：`iter/tcp4` — TCP 连接状态扫描器

**目标**：遍历所有 TCP 连接，输出四元组 + 状态，类似 `ss -t`

**教学点**：
- `SEC("iter/tcp4")` + `bpf_iter__tcp` 上下文
- 读取 `sock_common` 结构体字段
- 二进制输出（`bpf_seq_write`）+ 用户态解析
- 实际工具替代场景（替代 `ss`/`netstat`）

### 思路 3：`iter/bpf_map_elem` — BPF Map 内容导出器

**目标**：遍历指定 BPF map 的所有元素，导出 key/value

**教学点**：
- `SEC("iter/bpf_map_elem")` + `bpf_iter__bpf_map_elem` 上下文
- 读取 map 元素的 key/value 指针
- 对比 `bpftool map dump` 的替代方案
- 动态 map 类型处理

### 思路 4：Open-coded `bpf_for_each(num)` — 数字迭代器

**目标**：在 XDP 或 tracing 程序中用 `bpf_for_each(num, i, 0, N)` 遍历数字范围

**教学点**：
- `bpf_iter_num` kfunc 三元组
- `bpf_for_each` 宏的用法
- open-coded iterator 与 iterator 程序类型的区别
- 验证器对循环的处理

**BPF 侧**：
```c
SEC("tp/syscalls/sys_enter_openat")
int handle_open(void *ctx)
{
    int *i;
    bpf_for_each(num, i, 0, 10) {
        bpf_printk("i = %d", *i);
    }
    return 0;
}
```

### 思路 5：Pin 到 bpffs + `cat` 读取

**目标**：用 `bpftool iter pin` 将 iterator pin 到 `/sys/fs/bpf/`，用 `cat` 读取

**教学点**：
- `bpftool iter pin` 命令
- bpffs 挂载与 pin 机制
- `cat /sys/fs/bpf/my_iter` 触发遍历
- 与 `/proc` 系统的对比

**流程**：
```bash
bpftool iter pin ./iter.o /sys/fs/bpf/my_task_iter
cat /sys/fs/bpf/my_task_iter    # 输出所有进程
rm /sys/fs/bpf/my_task_iter     # 清理
```

### 推荐实施顺序

| 优先级 | 示例 | 理由 |
|---|---|---|
| 1 | 思路 1（task_file 参数化） | 在现有 features/bpf_iters 基础上递进，最小改动 |
| 2 | 思路 4（open-coded num） | 展示全新的 open-coded 概念，对比程序类型 |
| 3 | 思路 2（tcp4 扫描器） | 实用场景，替代 ss 命令 |
| 4 | 思路 5（pin + cat） | 展示 bpffs 集成 |
| 5 | 思路 3（map_elem 导出） | 较复杂，需处理动态 map 类型 |
