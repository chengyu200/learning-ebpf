# 14b-tcprtt

统计 TCP 平滑往返时间（smoothed RTT），按 log2 直方图展示。对应 bcc 的 `tcprtt` 工具。

## 做什么

- 内核态：`SEC("fentry/tcp_rcv_established")`，每次 TCP 收包时用 `BPF_CORE_READ` 读取 `tcp_sock->srtt_us`（右移 3 位还原真实值），按 log2 分桶累加到 hash map。
- 用户态：argp 命令行参数（端口/地址过滤、按地址分组、毫秒/微秒、间隔打印、平均值），轮询 hash map 打印 log2 直方图。

## 教学概念

- `fentry` + `BPF_PROG` 宏（对比 14-tcpstates 的 tracepoint）。fentry 比 kprobe 性能更好：直接通过 trampoline 获得参数，无需解析 `pt_regs`，且有 BTF 类型安全检查。
- `BPF_CORE_READ` 读取嵌套结构体字段（`sock → __sk_common → skc_daddr`、`tcp_sock → srtt_us`），CO-RE 自动适配不同内核的字段偏移。
- `BPF_MAP_TYPE_HASH` 以 `__u64`（地址或 0=全局）为 key、`struct hist`（含 slots 数组 + latency/cnt）为 value。
- log2 直方图分桶：`63 - __builtin_clzll(x)`，slot N 表示 `[2^(N-1), 2^N)`。
- `srtt_us` 在内核内部存储为 `actual_srtt << 3`，需右移 3 位还原。
- 字节序：`inet_sport` / `skc_dport` 是网络序，用 `bpf_ntohs` 转换后比较。

## 运行

```bash
make -C src/14b-tcprtt
sudo ./src/14b-tcprtt/tcprtt          # Ctrl-C 打印直方图
sudo ./src/14b-tcprtt/tcprtt -i 5 -d 30  # 每 5 秒打印一次，共 30 秒
```

### 参数

| 参数 | 说明 |
|---|---|
| `-i SEC` | 间隔秒数（默认 Ctrl-C 打印一次） |
| `-d SEC` | 总时长（默认 99999） |
| `-m` | 毫秒直方图（默认微秒） |
| `-T` | 输出时间戳 |
| `-p PORT` | 过滤本地端口 |
| `-P PORT` | 过滤远端端口 |
| `-a ADDR` | 过滤本地地址 |
| `-A ADDR` | 过滤远端地址 |
| `-b` | 按本地地址分桶 |
| `-B` | 按远端地址分桶 |
| `-e` | 显示平均 RTT |
| `-4` / `-6` | 只跟踪 IPv4 / IPv6 |

### 输出示例

```
$ sudo ./src/14b-tcprtt/tcprtt -i 3 -d 6 -e -B

Tracing TCP RTT... Hit Ctrl-C to end.

Address = 10.0.2.2     [AVG 238 usecs]
             usecs        : count    |distribution
          64 -> 127      : 281      |****************************************
         128 -> 255      : 32       |****
         256 -> 511      : 1        |

Address = 10.176.18.71 [AVG 102 usecs]
             usecs        : count    |distribution
          32 -> 63       : 92       |****************************************
```

## 与 14-tcpstates 的对比

| | 14-tcpstates | 14b-tcprtt |
|---|---|---|
| 挂载点 | fentry `tcp_rcv_established` | tracepoint `inet_sock_set_state` |
| 触发时机 | TCP 状态变迁 | 每次 TCP 收包 |
| 输出 | 逐条事件（状态 + 停留时间） | log2 直方图（RTT 分布） |
| Map 类型 | perf event array | hash map（key=地址） |
| 关注点 | 连接生命周期 | 网络延迟质量 |

## srtt 原理

TCP 的 smoothed RTT（sRTT）是内核维护的平滑往返时间估计值，用于超时重传计算（RFC 6298）：

```
SRTT <- (7/8) * SRTT + (1/8) * R    （R = 最新 RTT 样本）
```

内核 `tcp_sock->srtt_us` 存储为 `actual_srtt << 3`（固定小数点，3 位小数精度），因此 BPF 程序需要 `>> 3` 还原。每次 `tcp_rcv_established` 被调用时 sRTT 可能已更新，反映最近一次 ACK 的 RTT 估计。
