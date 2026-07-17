# cgroup

基于 cgroup 的网络流量策略：用 cgroup_skb 程序统计每个 cgroup 的出口包/字节数。

## 做什么

- 内核态：`SEC("cgroup_skb/egress")` 程序在根 cgroup 的出口路径上计数包数和字节数（per-cpu array map）。
- 用户态：用 `bpf_program__attach_cgroup` 挂到 `/sys/fs/cgroup`，周期性读取 per-cpu 计数并打印总和。

## 教学概念

- `cgroup_skb` 程序类型、`bpf_program__attach_cgroup` 挂载到 cgroup v2 根目录。
- cgroup 级别的网络可观测性与策略控制。
- `BPF_MAP_TYPE_PERCPU_ARRAY` 的 per-cpu 统计 + 用户态聚合。

## 运行

```bash
make -C src/cgroup
sudo ./src/cgroup/cgroup 2
# 产生网络流量（如 curl）后观察计数增长
```
