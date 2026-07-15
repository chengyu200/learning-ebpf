# 13-tcpconnlat

统计 TCP 主动连接（`connect`）的建连延迟。

## 做什么

- 内核态：在 `tcp_v4_connect` / `tcp_v6_connect` 上记录起始时间戳（哈希表，键为 `struct sock *`）；在 `tcp_rcv_state_process` 检测到状态离开 `TCP_SYN_SENT` 时计算延迟，通过 perf event array 输出 pid、端口、地址、延迟。
- 用户态：argp（`--pid`、`--min-ms`），轮询 perf buffer 打印。

## 教学概念

- kprobe on tcp 连接路径、`BPF_KPROBE` 取参数。
- `BPF_CORE_READ` 读 `struct sock` 的 `__sk_common` 字段（IPv4/IPv6 地址、端口）。
- `BPF_MAP_TYPE_PERF_EVENT_ARRAY` + `bpf_perf_event_output`。

## 运行

```bash
make -C src/13-tcpconnlat
sudo ./src/13-tcpconnlat
# 另开终端产生连接，例如：curl -s http://1.1.1.1 -o /dev/null
```
