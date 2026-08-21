# 85-iter-memcg-seq

用 `SEC("iter/cgroup")` BPF iterator 遍历 cgroup 层级，从每个 cgroup 获取 mem_cgroup 并输出内存使用信息。

## 什么是方案 A（iter/cgroup + mem_cgroup）

遍历所有 cgroup，通过 `cgroup->subsys[memory_cgrp_id]` 获取 mem_cgroup 的 css，再用 `container_of(css, mem_cgroup, css)` 得到 mem_cgroup，读取内存使用量并输出到 seq_file。

### 与 84-iter-memcg（方案 B）的对比

| 维度 | 84（方案 B open-coded） | 85（方案 A iter/cgroup） |
|------|----------------------|------------------------|
| SEC | `tp/syscalls/sys_enter_openat` | `SEC("iter/cgroup")` |
| 遍历对象 | 直接遍历 mem_cgroup css 树 | 遍历 cgroup 层级，从每个 cgroup 获取 mem_cgroup |
| 获取 mem_cgroup | `bpf_get_root_mem_cgroup()` + `bpf_for_each(css)` | `cgroup->subsys[memory_cgrp_id]` → `container_of` |
| 输出方式 | ringbuf 事件 | `BPF_SEQ_PRINTF` → `read(iter_fd)` |
| 触发方式 | 需要 openat 触发 | `read(iter_fd)` 直接读取 |
| 引用管理 | 需 `bpf_put_mem_cgroup()` 释放 | 无需（iter/cgroup 管理生命周期） |
| 精确性 | 精确遍历 mem_cgroup 树 | 遍历所有 cgroup，每个 cgroup 都有 mem_cgroup |

### 获取 mem_cgroup 的原理

cgroup v2 中，每个 cgroup 都有关联的 mem_cgroup（通过 memory cgroup 子系统）：

```c
/* cgroup->subsys[memory_cgrp_id] 指向 mem_cgroup.css */
struct cgroup_subsys_state *css = cg->subsys[memory_cgrp_id];

/* css 是 mem_cgroup 的第一个字段，container_of 转换 */
struct mem_cgroup *memcg = container_of(css, struct mem_cgroup, css);

/* 读取内存使用量 */
__u64 usage = memcg->memory.usage.counter;  /* atomic_long_t */
```

## 做什么

- 用 `SEC("iter/cgroup")` 遍历 cgroup 层级（从根 cgroup 开始，前序遍历）
- 对每个 cgroup，获取其关联的 mem_cgroup
- 输出：mem_cgroup ID、cgroup level、memory usage（字节）、swap usage（字节）、cgroup 路径

## 运行

```bash
make -C src/85-iter-memcg-seq
sudo ./src/85-iter-memcg-seq/iter-memcg-seq
# 指定子树：sudo ./src/85-iter-memcg-seq/iter-memcg-seq --cgroup /sys/fs/cgroup/system.slice
# 指定顺序：sudo ./src/85-iter-memcg-seq/iter-memcg-seq --order post
```

### 输出示例

```
=== Mem Cgroup Hierarchy (root=/sys/fs/cgroup, order=pre) ===

id         level  memory         swap           path
─────────  ─────  ──────────────  ─────────────  ──────────────────────────────
5          0      760312         245760         /
17         1      4096           397            /init.scope
21         1      32768          30720          /system.slice
69         2      1024           0              /system.slice/systemd-udevd.service
...
154        1      723456         215040         /user.slice
545        2      723456         215040         /user.slice/user-1000.slice
601        3      256000         54272          /user.slice/user-1000.slice/session-4.scope
...
```

## 教学概念

| 概念 | 说明 |
|------|------|
| `SEC("iter/cgroup")` | BPF iterator 遍历 cgroup 层级 |
| `bpf_program__attach_iter` | attach BPF iterator（需 `bpf_iter_attach_opts`） |
| `bpf_iter_create` + `read` | 用户态创建 iter_fd 并读取输出 |
| `cgroup->subsys[memory_cgrp_id]` | 从 cgroup 获取 mem_cgroup 的 css（`memory_cgrp_id=4`） |
| `container_of(css, mem_cgroup, css)` | 从 css 获取 mem_cgroup（css 是第一个字段） |
| `BPF_SEQ_PRINTF` | 输出到 seq_file（vs ringbuf） |
| `BPF_CORE_READ` | 安全读取内核结构体字段（CO-RE） |
| 无需引用管理 | iter/cgroup 管理生命周期（vs 方案 B 的 `bpf_put_mem_cgroup`） |

## 技术细节

### iter/cgroup attach 选项

```c
LIBBPF_OPTS(bpf_iter_attach_opts, opts,
    .link_info = &linfo,
    .link_info_len = sizeof(linfo),
);
linfo.cgroup.order = BPF_CGROUP_ITER_DESCENDANTS_PRE;  /* 前序遍历 */
linfo.cgroup.cgroup_fd = cg_fd;  /* 起始 cgroup（根 cgroup） */
```

| order | 说明 |
|-------|------|
| `SELF_ONLY` (1) | 仅遍历自身 |
| `DESCENDANTS_PRE` (2) | 前序遍历所有后代（默认） |
| `DESCENDANTS_POST` (3) | 后序遍历所有后代 |
| `ANCESTORS_UP` (4) | 从当前向上遍历祖先 |

### cgroup 路径构建

沿 `kernfs_node->__parent` 向上遍历，收集路径组件，然后反序输出（同 62-iter-cgroup）。

### atomic_long_t 读取

`page_counter->usage` 是 `atomic_long_t`（即 `atomic64_t`），其内部字段 `counter` 是 `s64`：

```c
__u64 usage = BPF_CORE_READ(memcg, memory.usage.counter);
```

## 文件结构

```
85-iter-memcg-seq/
├── Makefile                  # APP := iter-memcg-seq
├── iter-memcg-seq.bpf.c     # SEC("iter/cgroup") + mem_cgroup 信息 + BPF_SEQ_PRINTF
├── iter-memcg-seq.c          # 加载器 + read(iter_fd)
└── README.md
```
