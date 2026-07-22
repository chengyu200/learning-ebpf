# 51-cgroup-sysctl

监控 `/proc/sys/net/` 下的 sysctl 写入，通过 `BPF_PROG_TYPE_CGROUP_SYSCTL` 拦截并报告。

参考了 systemd 的 [sysctl-monitor](https://github.com/systemd/systemd/tree/v259-stable/src/network/bpf/sysctl-monitor) 实现（commit 6d9ef22），简化了过滤逻辑，保留核心教学概念。

## 做什么

- **内核态**：挂载 `cgroup/sysctl` 程序到根 cgroup，拦截所有进程对 `/proc/sys/` 的写操作
  - 只处理写操作（`ctx->write == 1`），读操作直接放行
  - 只监控 `net/` 前缀的 sysctl（用 `bpf_strncmp` 比较）
  - 获取 sysctl 路径、旧值、新值，值不同时通过 ringbuf 发送事件
  - 始终返回 1（放行写入，仅监控不阻止）
- **用户态**：轮询 ringbuf，格式化打印 sysctl 写入事件

## 教学概念

| 概念 | 说明 |
|------|------|
| `BPF_PROG_TYPE_CGROUP_SYSCTL` | 拦截 cgroup 内进程的 sysctl 读写 |
| `bpf_sysctl_get_name` | 获取 sysctl 路径（如 `net/ipv4/ip_forward`，不含 `/proc/sys/` 前缀） |
| `bpf_sysctl_get_current_value` | 获取写入前的当前值 |
| `bpf_sysctl_get_new_value` | 获取正在写入的新值 |
| `bpf_strncmp` | 内核字符串比较 helper（避免手写循环触发 verifier） |
| `bpf_program__attach_cgroup` | 将 BPF 程序挂到 cgroup（根 cgroup = 监控所有进程） |
| 返回值 | `1` = 放行，`0` = 阻止（本示例始终放行） |

## 与 systemd 实现的差异

| 特性 | systemd | 本示例 |
|------|---------|--------|
| cgroup_map 过滤 | 用 `bpf_current_task_under_cgroup` 忽略自己产生的写入 | 去掉（简化，所有写入都报告） |
| 字符串处理 | `chop()` 函数去除尾部换行符 | 去掉（直接比较含换行符的值） |
| ringbuf API | `bpf_ringbuf_output` | `bpf_ringbuf_reserve`/`submit`（更现代） |
| 监控范围 | systemd-networkd 管理的 sysctl | 所有 `/proc/sys/net/` 写入 |

## 运行

```bash
make -C src/51-cgroup-sysctl
sudo ./src/51-cgroup-sysctl/sysctl-monitor
# 另开终端：
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
```

## 输出示例

```
Monitoring sysctl writes under /proc/sys/net/... Ctrl-C
TIME     PID     COMM             PATH                                OLD → NEW
06:53:54 120331  bash             net/ipv4/ip_forward                 0 → 1
06:53:55 120331  bash             net/ipv4/ip_forward                 1 → 0
06:53:55 120331  bash             net/ipv4/conf/all/forwarding        0 → 1
06:53:55 120331  bash             net/ipv4/conf/all/forwarding        1 → 0
```

- 值相同的写入（如已经是 0 再写 0）不会产生事件
- 非 `net/` 前缀的 sysctl（如 `kernel/printk`）不会产生事件
