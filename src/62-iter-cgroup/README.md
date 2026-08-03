# 62-iter-cgroup — Cgroup 层级遍历

## 概述

用 `SEC("iter/cgroup")` 遍历 cgroup v2 层级树，输出每个 cgroup 的 id、level、子节点数、名称。支持多种遍历顺序和指定起始 cgroup。

### 遍历顺序

| `--order` | 枚举值 | 说明 |
|---|---|---|
| `self` | `BPF_CGROUP_ITER_SELF_ONLY` (1) | 仅遍历指定 cgroup 自身 |
| `pre` | `BPF_CGROUP_ITER_DESCENDANTS_PRE` (2) | 前序遍历所有后代（默认） |
| `post` | `BPF_CGROUP_ITER_DESCENDANTS_POST` (3) | 后序遍历所有后代 |
| `ancestors` | `BPF_CGROUP_ITER_ANCESTORS_UP` (4) | 从指定 cgroup 向上遍历祖先 |

### iter/cgroup 的 attach 要求

与 `iter/task` 不同，`iter/cgroup` **必须**通过 `bpf_iter_attach_opts` 指定：
- `linfo.cgroup.order`：遍历顺序
- `linfo.cgroup.cgroup_fd`：起始 cgroup 的 fd（通过 `open("/sys/fs/cgroup/...", O_RDONLY)` 获取）

不指定时 attach 会返回 `-EINVAL`。

## 编译与运行

```bash
make -C src/62-iter-cgroup

# 前序遍历根 cgroup 的所有后代（默认）
sudo ./src/62-iter-cgroup/iter-cgroup

# 仅遍历指定 cgroup 自身
sudo ./src/62-iter-cgroup/iter-cgroup --order self --cgroup /sys/fs/cgroup/system.slice

# 从指定 cgroup 向上遍历祖先
sudo ./src/62-iter-cgroup/iter-cgroup --order ancestors --cgroup /sys/fs/cgroup/system.slice

# 后序遍历
sudo ./src/62-iter-cgroup/iter-cgroup --order post
```

## 输出示例

```
=== Cgroup Hierarchy (root=/sys/fs/cgroup, order=pre) ===
id       level  nrdesc   name
1        0      62       
31       1      0        init.scope
75       1      34       system.slice
798      2      0        system-modprobe.slice
974      2      0        sysroot.mount
1331     2      1        system-serial\x2dgetty.slice
5198     3      0        serial-getty@ttyAMA0.service
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `SEC("iter/cgroup")` | cgroup iterator 程序 |
| `bpf_iter__cgroup` 上下文 | 包含 `meta` + `cgroup` 指针 |
| `bpf_iter_attach_opts` | 必须指定 `cgroup.order` + `cgroup.cgroup_fd` |
| `BPF_CGROUP_ITER_DESCENDANTS_PRE` | 前序遍历后代（根→子→孙） |
| `bpf_probe_read_kernel_str` | 读取内核字符串（`kn->name`）到栈缓冲区 |
| `BPF_CORE_READ` | CO-RE 读取 `cgroup`/`kernfs_node` 结构体字段 |
