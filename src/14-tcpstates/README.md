# 14-tcpstates

记录 TCP 连接状态变迁及每段状态停留时间。

## 做什么

- 内核态：挂钩 `tracepoint/sock/inet_sock_set_state`，每次状态变迁时与上次时间戳（哈希表，键为 `struct sock *`）求差得到该状态停留时长，通过 perf event array 输出。
- 用户态：argp（`--sport`、`--dport`），轮询 perf buffer，把状态号映射为名字打印。

## 教学概念

- tracepoint `sock/inet_sock_set_state`（比 kprobe 更稳定）。
- 哈希表按 `struct sock *` 关联相邻事件。
- 端口过滤用单独的哈希集合。

## 运行

```bash
make -C src/14-tcpstates
sudo ./src/14-tcpstates
# 另开终端产生连接，例如：curl -s http://1.1.1.1 -o /dev/null
```
