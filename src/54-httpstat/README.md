# 54-httpstat — HTTP 流量统计

## 概述

用 eBPF socket filter 捕获 HTTP 流量，在 BPF 侧解析 HTTP 请求方法、URL 路径、响应状态码，通过 ringbuf 发送到用户态。用户态实时打印每个 HTTP 数据包的详细信息，同时聚合统计，每 20 秒（或 Ctrl-C）打印汇总报告。

### 与 23-http 的区别

| 维度 | 23-http | 54-httpstat |
|---|---|---|
| TCP 头解析 | 硬编码 14 字节 | ✅ 正确解析 data_offset |
| HTTP 方法识别 | ❌ 不解析 | ✅ bpf_strncmp 识别 6 种方法 |
| URL 路径提取 | ❌ | ✅ 有界循环提取 path |
| 状态码解析 | ❌ | ✅ 解析 3 位状态码 |
| 输出 | ringbuf 原始 payload | ringbuf 结构化 http_event |
| 用户态 | dump 原始字节 | 实时打印 + 聚合统计 + 报告 |

## 架构

```
┌─ BPF 内核态 (httpstat.bpf.c) ───────────────────────┐
│  SEC("socket") socket_handler                       │
│  AF_PACKET + SO_ATTACH_BPF                         │
│                                                     │
│  Ethernet → IP → TCP → payload                     │
│  payload 判断：                                      │
│  ├─ "GET "/"POST " 等 → 请求：method + path        │
│  └─ "HTTP/"          → 响应：status code           │
│  输出：ringbuf → http_event                         │
└─────────────────────┬──────────────────────────────┘
                      │ ringbuf
                      ▼
┌─ 用户态 (httpstat.c) ─────────────────────────────┐
│  ring_buffer__poll → handle_event                   │
│                                                     │
│  实时输出：每个 HTTP 包打印一行                      │
│    [REQ] src:port -> dst:port  METHOD path (bytes) │
│    [RSP] src:port -> dst:port  HTTP/status (bytes) │
│                                                     │
│  聚合统计（每 20 秒 / Ctrl-C 打印报告）：             │
│    方法分布 | 状态码分布 | URL Top N | IP Top N      │
└─────────────────────────────────────────────────────┘
```

## 统计指标

- **实时打印**：每个 HTTP 请求/响应包打印 `源IP:端口 -> 目的IP:端口  方法/状态码  路径  (字节数)`
- **方法分布**：GET / POST / PUT / DELETE / HEAD / PATCH / OTHER 计数
- **状态码分布**：100-599 各状态码计数
- **URL 路径 Top 10**：按请求次数排序
- **源 IP Top 10**：按请求次数排序
- **目的 IP Top 10**：按请求次数排序
- **总请求数/响应数 + 字节数**

## 编译与运行

```bash
# 编译
make -C src/54-httpstat

# 启动 HTTP 服务（产生流量用）
python3 -m http.server 8080 &

# 启动 httpstat（监听 lo 接口）
sudo ./src/54-httpstat/httpstat lo

# 另开终端产生 HTTP 流量
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/api/v1/users
curl -X POST http://127.0.0.1:8080/submit
curl -X DELETE http://127.0.0.1:8080/item/1
curl http://127.0.0.1:8080/notfound

# 实时打印每个包，每 20 秒自动打印报告，或 Ctrl-C 手动触发
```

## 实时输出示例

```
[REQ] 127.0.0.1:39902 -> 127.0.0.1:8080  GET /  (78 bytes)
[RSP] 127.0.0.1:8080 -> 127.0.0.1:39902  HTTP/200  (157 bytes)
[REQ] 127.0.0.1:39922 -> 127.0.0.1:8080  POST /submit  (85 bytes)
[RSP] 127.0.0.1:8080 -> 127.0.0.1:39922  HTTP/501  (163 bytes)
```

## 汇总报告示例

```
========================================
     HTTP Traffic Statistics Report
========================================

--- Method Distribution ---
  GET      12
  POST     4

--- Status Code Distribution ---
  200		 12
  501		 4

--- Total ---
  Requests:  16 (1356 bytes)
  Responses: 16 (2616 bytes)

--- Top 10 Paths ---
  1   /                                        4
  2   /api/v1/users                            4
  3   /submit                                  4
  4   /notfound                                4

--- Top 10 Source IPs ---
  1   127.0.0.1            16

--- Top 10 Destination IPs ---
  1   127.0.0.1            16
```

## 文件结构

```
54-httpstat/
├── Makefile
├── README.md
├── httpstat.h           # 共享：事件结构体 + 常量
├── httpstat.bpf.c       # BPF socket filter：解析 HTTP，发 ringbuf
└── httpstat.c           # 用户态：AF_PACKET attach + 实时打印 + 聚合统计 + 报告
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `BPF_PROG_TYPE_SOCKET_FILTER` | socket filter 程序类型 |
| `AF_PACKET` + `SO_ATTACH_BPF` | raw socket + BPF 挂载方式 |
| `bpf_skb_load_bytes` | 从 skb 按偏移读取数据 |
| `bpf_strncmp` | BPF 字符串比较（识别 HTTP 方法） |
| TCP data offset | 正确解析 TCP 头长度（`doff` 字段） |
| `BPF_MAP_TYPE_RINGBUF` | ringbuf 发送结构化事件到用户态 |
| 有界循环 | BPF 中的安全循环（路径提取） |
| 用户态聚合 | 固定大小数组 + 线性搜索 + qsort 排序 |
| `inet_ntop` vs `inet_ntoa` | `inet_ntoa` 用静态缓冲区，同一 printf 中两次调用会互相覆盖；`inet_ntop` 线程安全 |
| `sigaction` + `SIGALRM` | 定时触发统计报告（20 秒间隔） |

## `__sk_buff` 字段可用性说明

`struct __sk_buff` 中有 `data` 和 `data_end` 字段，看起来可以直接做指针解引用访问包数据（像 XDP/TC 那样）。但实测发现 **socket filter 程序类型不允许访问这两个字段**——验证器报错 `invalid bpf_context access off=80`。

这是 socket filter 与 TC/XDP 的本质区别：

| `__sk_buff` 字段 | socket_filter | TC (sched_cls) | XDP (`xdp_md`) |
|---|---|---|---|
| `protocol`, `pkt_type`, `ifindex` | ✅ | ✅ | — |
| `data` / `data_end` | ❌ | ✅ | ✅（`xdp_md.data`） |
| `remote_ip4`, `local_ip4` 等 | ❌ | ❌ | — |

因此 socket filter **必须**用 `bpf_skb_load_bytes` 读取包数据，无法像 41-xdp-tcpdump / 20-tc 那样用直接指针方式。`__sk_buff` 中 `remote_ip4` / `local_ip4` / `remote_port` / `local_port` 等字段标注为"仅 `BPF_PROG_TYPE_SK_SKB` 可访问"，socket filter 同样不可用。

如需直接指针方式，可改用 TC（`SEC("tc")` + `bpf_tc_hook_create` + `bpf_tc_attach`），但会改变用户态 attach 方式。
