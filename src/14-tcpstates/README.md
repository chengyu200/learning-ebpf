# 14-tcpstates

记录 TCP 连接状态变迁及每段状态停留时间。

## 做什么

- 内核态：挂钩 `tracepoint/sock/inet_sock_set_state`，每次状态变迁时与上次时间戳（哈希表，键为 `struct sock *`）求差得到该状态停留时长，通过 perf event array 输出。
- 用户态：argp（`--sport`、`--dport`），轮询 perf buffer，把状态号映射为名字打印。

## 教学概念

- tracepoint `sock/inet_sock_set_state`（比 kprobe 更稳定）。
- 哈希表按 `struct sock *` 关联相邻事件。
- 端口过滤用单独的哈希集合。
- tracepoint 的 `sport`/`dport` 在内核侧已做 `ntohs()` 转为 host 序，用户态打印时**不应再做** `ntohs`。

## 运行

```bash
make -C src/14-tcpstates
sudo ./src/14-tcpstates
# 另开终端产生连接，例如：curl -s http://127.0.0.1 -o /dev/null
```

## 输出示例与分析

以 `curl 127.0.0.1` 访问 nginx 为例，一次完整的 TCP 连接（含挥手）输出如下：

```
TIME     PID     TIMESTAMP(us)         DELTA(us)           OLDSTATE       -> NEWSTATE ADDR

10:49:42 207928  431517.443679     0.000000 CLOSE        -> SYN_SENT     127.0.0.1:0     -> 127.0.0.1:80
10:49:42 207928  431517.443812     0.000133 SYN_SENT     -> ESTABLISHED  127.0.0.1:55148 -> 127.0.0.1:80
10:49:42 207928  431517.443835     0.000000 LISTEN       -> SYN_RECV     127.0.0.1:80    -> 127.0.0.1:55148
10:49:42 207928  431517.443885     0.000050 SYN_RECV     -> ESTABLISHED  127.0.0.1:80    -> 127.0.0.1:55148
10:49:42 207928  431517.444187     0.000375 ESTABLISHED  -> FIN_WAIT1    127.0.0.1:55148 -> 127.0.0.1:80
10:49:42 207928  431517.444215     0.000329 ESTABLISHED  -> CLOSE_WAIT   127.0.0.1:80    -> 127.0.0.1:55148
10:49:42 184208  431517.444294     0.000079 CLOSE_WAIT  -> LAST_ACK     127.0.0.1:80    -> 127.0.0.1:55148
10:49:42 184208  431517.444411     0.000224 FIN_WAIT1   -> FIN_WAIT2    127.0.0.1:55148 -> 127.0.0.1:80
10:49:42 184208  431517.444438     0.000026 FIN_WAIT2   -> CLOSE        127.0.0.1:55148 -> 127.0.0.1:80
10:49:42 184208  431517.444457     0.000162 LAST_ACK   -> CLOSE        127.0.0.1:80    -> 127.0.0.1:55148
```

### 状态转换流程图

```
    curl (PID 207928)                           nginx (PID 184208)
    ================                           ==================

 ① CLOSE → SYN_SENT                          (nginx 在 LISTEN)
    curl connect() 发 SYN
    sport=0:此时源端口尚未分配
    │
    │  (lo 回环:SYN 立即到达 nginx)
    │                                         ③ LISTEN → SYN_RECV
    │  ◄── SYN-ACK ──                            nginx 收到 SYN,回 SYN-ACK
    │
 ② SYN_SENT → ESTABLISHED                        │
    curl 收到 SYN-ACK                            │
    │  ── ACK ──►                               ④ SYN_RECV → ESTABLISHED
    │                                            nginx 收到 ACK,连接建立
    │  ── GET / HTTP/1.1 ──►                    │
    │  ◄── HTTP/1.1 200 OK ──                   │
    │                                            │
 ⑤ ESTABLISHED → FIN_WAIT1                      │
    curl close() 发 FIN                          │
    │  ── FIN ──►                               ⑥ ESTABLISHED → CLOSE_WAIT
    │  ◄── ACK ──                                nginx 收到 FIN
 ⑧ FIN_WAIT1 → FIN_WAIT2                        │
    curl 收到对 FIN 的 ACK                       │
    │                                         ⑦ CLOSE_WAIT → LAST_ACK
    │                                            nginx close() 发 FIN
    │  ◄── FIN ──                               │
 ⑨ FIN_WAIT2 → CLOSE                            │
    curl 收到 FIN,回 ACK                         │
    │  ── ACK ──►                               ⑩ LAST_ACK → CLOSE
    │                                            nginx 收到 ACK,连接关闭
```

### 逐条分析

| # | Δ(us) | 方向 | 状态变化 | 触发原因 |
|---|---|---|---|---|
| ① | 0 | client | CLOSE→SYN_SENT | curl 调 `connect()`，内核发 SYN；sport=0 因为端口尚未分配 |
| ② | 133 | client | SYN_SENT→ESTABLISHED | 收到 SYN-ACK，连接建立（133μs 往返） |
| ③ | 0 | server | LISTEN→SYN_RECV | nginx 收到 SYN；localhost 下与①几乎同时 |
| ④ | 50 | server | SYN_RECV→ESTABLISHED | nginx 收到 ACK，三次握手完成 |
| ⑤ | 375 | client | ESTABLISHED→FIN_WAIT1 | curl 收完响应调 `close()`，发 FIN；375μs = HTTP 交互时间 |
| ⑥ | 329 | server | ESTABLISHED→CLOSE_WAIT | nginx 收到 curl 的 FIN |
| ⑦ | 79 | server | CLOSE_WAIT→LAST_ACK | nginx worker 调 `close()`，发 FIN |
| ⑧ | 224 | client | FIN_WAIT1→FIN_WAIT2 | curl 收到 nginx 对 FIN 的 ACK |
| ⑨ | 26 | client | FIN_WAIT2→CLOSE | curl 收到 nginx 的 FIN，回 ACK |
| ⑩ | 162 | server | LAST_ACK→CLOSE | nginx 收到最后的 ACK，连接完全关闭 |

### 关键观察

1. **PID 变化**：前 6 条 PID=207928(curl)，后 4 条 PID=184208(nginx worker)。localhost 下握手阶段都在 curl 的 `connect()` 上下文完成；关闭阶段 nginx worker 主动 `close()` 触发后半段。

2. **sport=0**：① 中源端口为 0，因为内核 `tcp_set_state(TCP_SYN_SENT)` 在 `inet_sport` 赋值**之前**触发 tracepoint。

3. **全程 778μs**（.443679→.444457），其中 HTTP 交互仅 375μs（④→⑤），握手 133μs（①→②），挥手 270μs（⑤→⑩）。

4. **无 TIME_WAIT**：client 先发 FIN 又先收到 FIN，FIN_WAIT2 直接转 CLOSE，跳过了 TIME_WAIT（只有"主动关闭且最后收到 ACK 的一方"才进 TIME_WAIT）。
