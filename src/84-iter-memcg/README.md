# 84-iter-memcg

用 BPF open-coded iterator（`bpf_for_each(css, ...)`）遍历系统上所有 mem_cgroup，输出每个 mem_cgroup 的内存使用量、swap 使用量和 cgroup 路径名。

## 什么是 mem_cgroup 遍历

`mem_cgroup`（memory cgroup）是 Linux 内核中控制内存使用的 cgroup 子系统。每个 mem_cgroup 通过 `struct cgroup_subsys_state css` 字段链接成一棵树。BPF 可以通过 open-coded iterator 遍历这棵树，读取每个 mem_cgroup 的内存统计信息。

### 遍历机制

```
bpf_get_root_mem_cgroup()          ← 获取 root mem_cgroup（__ksym kfunc）
    ↓
bpf_for_each(css, css, &root->css, 0)   ← open-coded iterator 遍历 css 子树
    ↓
container_of(css, mem_cgroup, css)      ← 从 css 获取 mem_cgroup
    ↓
memcg->memory.usage                      ← 读取内存使用量
memcg->css.cgroup->kn->name             ← 读取 cgroup 路径名
```

### 关键内核源码

- `bpf_get_root_mem_cgroup()`：返回 root `struct mem_cgroup *`（`__ksym`）
- `bpf_iter_css_new/next/destroy`：open-coded css iterator 的底层 kfuncs
- `bpf_for_each(css, ...)`：libbpf 宏，封装了上述 kfuncs

## 做什么

- 用 `bpf_get_root_mem_cgroup()` 获取 root mem_cgroup
- 用 `bpf_for_each(css, ...)` 遍历所有 mem_cgroup
- 读取每个 mem_cgroup 的：
  - `memcg_id`（css serial_nr）
  - `memory_usage`（`memcg->memory.usage`，字节）
  - `swap_usage`（`memcg->swap.usage`，字节）
  - `cgroup_name`（`css->cgroup->kn->name`）
  - `level`（cgroup 层级深度）
- 通过 ringbuf 发送事件到用户态

## 运行

```bash
make -C src/84-iter-memcg
sudo ./src/84-iter-memcg/iter-memcg
# 或指定 PID：sudo ./src/84-iter-memcg/iter-memcg --pid 1234
```

### 输出示例

```
BPF mem_cgroup iterator attached (target_pid=12345)
Triggering openat to start iteration...

memcg_id  level    cgroup                                    memory        swap
────────  ───────  ──────────────────────────────────────  ────────────  ────────────
  1       0        /                                         1234 MB       0 B
  2       1        /user.slice                               567 MB        0 B
  3       2        /user.slice/user-1000.slice               234 MB        0 B
  4       1        /system.slice                             89 MB         0 B
  5       1        /ai_inference                             12 MB         0 B

Done.
```

## 教学概念

| 概念 | 说明 |
|------|------|
| `bpf_get_root_mem_cgroup()` | 获取 root mem_cgroup（`__ksym` kfunc） |
| `bpf_for_each(css, ...)` | open-coded iterator 遍历 css 子树 |
| `bpf_iter_css_new/next/destroy` | 底层 kfuncs（由 `bpf_for_each` 封装） |
| `container_of(css, mem_cgroup, css)` | 从 css 获取 mem_cgroup（css 是第一个字段） |
| `BPF_CORE_READ` | 安全读取内核结构体字段（CO-RE） |
| `mem_cgroup->memory.usage` | `atomic_long_t` 内存使用量（字节） |
| `css->cgroup->kn->name` | cgroup 路径名（通过 kernfs_node） |
| `css->serial_nr` | mem_cgroup 唯一标识 |

## 技术细节

### open-coded iterator（bpf_for_each）

`bpf_for_each(css, cur, start, flags)` 是 libbpf 提供的宏，展开为：

```c
struct bpf_iter_css ___it __attribute__((cleanup(bpf_iter_css_destroy)));
bpf_iter_css_new(&___it, start, flags);
while ((cur = bpf_iter_css_next(&___it))) {
    // 循环体
}
// cleanup 属性自动调用 bpf_iter_css_destroy
```

`flags` 使用 `BPF_CGROUP_ITER_ORDER_*` 枚举值：

| flags | 值 | 说明 |
|-------|---|------|
| `BPF_CGROUP_ITER_ORDER_UNSPEC` | 0 | 未指定（不遍历） |
| `BPF_CGROUP_ITER_SELF_ONLY` | 1 | 仅遍历自身 |
| `BPF_CGROUP_ITER_DESCENDANTS_PRE` | 2 | 前序遍历所有后代（包括自身） |
| `BPF_CGROUP_ITER_DESCENDANTS_POST` | 3 | 后序遍历所有后代 |
| `BPF_CGROUP_ITER_ANCESTORS_UP` | 4 | 从当前向上遍历祖先 |
| `BPF_CGROUP_ITER_CHILDREN` | 5 | 仅遍历直接子节点 |

**重要**：`flags=0` (UNSPEC) 不会遍历任何节点！必须显式指定 `BPF_CGROUP_ITER_DESCENDANTS_PRE`(2) 才能遍历所有后代。

### container_of 获取 mem_cgroup

`struct mem_cgroup` 的第一个字段是 `struct cgroup_subsys_state css`：

```c
struct mem_cgroup {
    struct cgroup_subsys_state css;  // ← 第一个字段
    struct page_counter memory;
    ...
};
```

因此 `container_of(css, struct mem_cgroup, css)` 可以直接从 css 指针获取 mem_cgroup 指针。

### 读取内存使用量

`mem_cgroup->memory` 是 `struct page_counter`，其 `usage` 字段是 `atomic_long_t`：

```c
__u64 usage = BPF_CORE_READ(memcg, memory.usage.counter);
```

`counter` 是 `atomic_long_t` 的内部字段，通过 `BPF_CORE_READ` 读取其值。

### 与其他 iter 示例的对比

| 示例 | 遍历对象 | 机制 |
|------|---------|------|
| 57-iter-task-file | task 的文件 | `SEC("iter/task_file")` |
| 58-iter-open-coded | 数字 | `bpf_for(i, 0, N)` |
| 59-iter-vma | task 的 VMA | `SEC("iter/task_vma")` |
| 60-iter-bpf-map | BPF map 元素 | `SEC("iter/bpf_map_elem")` |
| 62-iter-cgroup | cgroup 层级 | `SEC("iter/cgroup")` |
| **84-iter-memcg** | **mem_cgroup** | **`bpf_for_each(css, ...)` open-coded** |

## 文件结构

```
84-iter-memcg/
├── Makefile              # APP := iter-memcg
├── iter-memcg.h            # 共享：event 结构
├── iter-memcg.bpf.c        # BPF 程序（bpf_get_root_mem_cgroup + bpf_for_each css）
├── iter-memcg.c            # 加载器 + ringbuf 消费
└── README.md
```
