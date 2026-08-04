# 64-fsession

用 `BPF_TRACE_FSESSION`（Function Session）测量 `vfs_read` 函数延迟。

## 什么是 FSESSION

FSESSION = Function Session：**一个 BPF 程序**同时在目标函数的入口（fentry）和出口（fexit）执行，通过 `session cookie` 在入口和出口之间共享数据。

```
vfs_read() 入口 → BPF 程序执行（is_return=false）
                      ↓ 存储时间戳到 session cookie
vfs_read() 执行
                      ↓
vfs_read() 出口 → 同一个 BPF 程序再次执行（is_return=true）
                      ↓ 读取 cookie 中的时间戳，计算延迟
```

## 与传统方案对比

| 特性 | kprobe+kretprobe（lesson 33） | fentry+fexit（两个程序） | **FSESSION** |
|------|------|------|------|
| 程序数量 | 2 | 2 | **1** |
| 上下文共享 | HASH map（按 tid） | HASH map（按 tid） | **session cookie（内核内置）** |
| 需要 BTF | 否 | 是 | **是** |
| 性能 | 中（int3 断点） | 高（trampoline） | **高（trampoline）** |
| 代码复杂度 | 中（两个程序+map） | 中 | **低（一个程序，无 map）** |

## 教学概念

| 概念 | 说明 |
|------|------|
| `SEC("fsession/vfs_read")` | libbpf 自动解析为 fentry+fexit trampoline |
| `bpf_session_is_return(ctx)` | kfunc：返回 true=函数返回阶段，false=入口阶段 |
| `bpf_session_cookie(ctx)` | kfunc：返回 `__u64*` 指针，入口存数据、出口取数据（per-call 私有） |
| `BPF_TRACE_FSESSION` | attach type 58，fentry+fexit 的合并版 |

## 运行

```bash
make -C src/53-fsession
sudo ./src/53-fsession/fsession
# 另开终端：cat /etc/hostname, ls, curl ...
# Ctrl-C 查看统计 + 直方图

# 或指定运行时间：
sudo ./src/53-fsession/fsession 5  # 5 秒后自动停止
```

## 输出示例

```
Measuring vfs_read latency via BPF_TRACE_FSESSION...
#       PID      COMM              LATENCY
1       pid=290620   Worker            3792 ns (3.79 us)
2       pid=290620   opencode          1167 ns (1.17 us)
3       pid=290620   opencode          1208 ns (1.21 us)

═══════════════════════════════════════════════════════════════
  vfs_read latency statistics (BPF_TRACE_FSESSION)
═══════════════════════════════════════════════════════════════
  Total samples:  3
  Average:        2055.67 ns  (2.06 us)
  Min:            1167 ns
  Max:            3792 ns  (3.79 us)

  log2 latency histogram (ns):
  range          count      : graph
  2^10 - 2^11   2          : 100.00% |****************************************
  2^11 - 2^12   1          :  50.00% |*************************
═══════════════════════════════════════════════════════════════
```
