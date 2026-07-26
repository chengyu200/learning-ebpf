# 53-transparent-proxy — 基于 eBPF 的透明流量劫持代理

## 概述

本示例演示如何用 **eBPF `cgroup/connect4`** 实现透明流量劫持：客户端 `connect(127.0.0.1:8080)` 被 BPF 程序改写到 sidecar:15006，sidecar 查原始目的后回源到 server:8080，对客户端和 server 完全透明。同时用 **sockops + sk_msg/SOCKHASH** 对本地回环流量加速，绕过 TCP/IP 协议栈。

这是 service mesh（如 Istio ambient 模式、Cilium）做流量拦截的核心技术。

### 数据流

```
┌── cgroup: /sys/fs/cgroup/ebpf-proxy-demo/ ──────────────────────┐
│                                                                  │
│  BPF 程序（由 sidecar 加载）：                                     │
│  ① cgroup/connect4  hijack_connect                              │
│  ② sockops          bpf_sockops_handler                          │
│                                                                  │
│  ┌───────┐  connect(127.0.0.1:8080)                               │
│  │ Client│ ──────┐                                               │
│  │(curl) │       │ ① BPF 改写 dst→15006 + 存 orig_dst[cookie]   │
│  └───────┘       ▼                                               │
│             ┌──────────┐  listen :15006                          │
│             │  Sidecar │ ② sockops 桥接 cookie→{ip,port}         │
│             │ (BPF +   │ ③ accept → getpeername → 查 conn_map   │
│             │  proxy)  │    → orig_dst = 127.0.0.1:8080          │
│             │          │ ④ connect(127.0.0.1:8080) PID skip     │
│             └────┬─────┘ ⑤ 双向 pipe                             │
│                  ▼                                               │
│             ┌──────────┐  listen :8080                           │
│             │  Server  │  纯 HTTP echo（无 BPF）                  │
│             └──────────┘                                         │
└──────────────────────────────────────────────────────────────────┘
```

## 关键设计

### 1. 为什么需要 sockops 桥接？

`cgroup/connect4` 在 `connect()` 早期触发，**此时客户端 ephemeral 源端口尚未分配**。因此 connect4 无法直接以源端口为 key。解决方法：

| 阶段 | 钩子 | 操作 |
|---|---|---|
| 1 | connect4 | 以 `socket cookie` 为 key 存 orig_dst |
| 2 | sockops (ACTIVE_ESTABLISHED) | cookie → 客户端源 {ip,port} 桥接，写入 conn_map |
| 3 | sidecar accept | `getpeername()` 取 {ip,port} → 查 conn_map → 得 orig_dst |

`bpf_get_socket_cookie()` 在 connect4 与 sockops 中对同一 socket 返回同一 cookie（内核 ≥5.7）。

### 2. 防递归

sidecar 自身 `connect(127.0.0.1:8080)` 回源时也会触发 connect4。通过 `sidecar_pid_map[0]` 存 sidecar PID，BPF 中 `bpf_get_current_pid_tgid()` 匹配则跳过改写。

### 3. cgroup 隔离

sidecar 创建 `/sys/fs/cgroup/ebpf-proxy-demo/` 并移入自身。BPF 仅挂在该子 cgroup，**不影响宿主其他进程**。

## 教学概念

| 概念 | 说明 |
|---|---|
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | cgroup 级 socket 地址改写 |
| `cgroup/connect4` | 拦截 IPv4 connect() 系统调用 |
| `bpf_sock_addr` | connect4 上下文，可改 `user_ip4`/`user_port` |
| `bpf_get_socket_cookie` | 获取 socket 唯一标识（跨钩子稳定） |
| `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` | 主动连接建立回调 |
| `BPF_MAP_TYPE_ARRAY` / `HASH` | PID map / orig_dst / conn_map |
| `getsockopt(SO_COOKIE)` | 用户态获取 socket cookie（备用） |

## 文件结构

```
53-transparent-proxy/
├── Makefile          # 双二进制：sidecar + server
├── proxy.h           # 共享常量（端口、cgroup 路径、结构体）
├── sidecar.bpf.c     # BPF 内核态：connect4 + sockops + 3 maps
├── sidecar.c         # 用户态：BPF loader + TCP 代理 + cgroup 管理
├── server.c          # 纯 HTTP echo（无 BPF）
└── run-demo.sh       # 一键演示
```

## 编译与运行

```bash
# 编译
make -C src/53-transparent-proxy

# 一键演示（需 root）
sudo ./src/53-transparent-proxy/run-demo.sh

# 或手动分步：
# 1. 启动 sidecar（自建 cgroup + 加载 BPF + listen :15006）
sudo ./src/53-transparent-proxy/sidecar &

# 2. 将测试 shell 移入 cgroup
echo $$ | sudo tee /sys/fs/cgroup/ebpf-proxy-demo/cgroup.procs

# 3. 启动 server
./src/53-transparent-proxy/server &

# 4. 测试（在 cgroup 内的 shell 中）
curl http://127.0.0.1:8080/hello
# 预期：收到 server 的 200 响应，sidecar 日志显示劫持

# 5. 查看 BPF trace 输出
sudo cat /sys/kernel/tracing/trace_pipe
```

## 验证点

| # | 测试 | 预期 |
|---|---|---|
| 1 | `curl http://127.0.0.1:8080/hello` | 200 + server 响应（透明） |
| 2 | sidecar stdout | `hijack: cookie=... 8080->15006` + `accepted, orig=127.0.0.1:8080` |
| 3 | trace_pipe | `hijack:` + `sockops: bridge` 日志 |
| 4 | sidecar 退出后 `ls /sys/fs/cgroup/` | `ebpf-proxy-demo` 已清理 |
| 5 | 宿主其他进程 `curl 127.0.0.1:8080`（不在 cgroup） | 直连 server，无劫持 |

## 透明性限制（v1）

v1 未实现 `cgroup/getpeername4`，客户端调用 `getpeername()` 会看到 `127.0.0.1:15006` 而非原始 `127.0.0.1:8080`。**curl/HTTP 不受影响**（不检查 peer name），但 TLS 或某些协议可能异常。v2 可加 `cgroup/getpeername4` 恢复原始 peer 地址。

## 后续迭代

| 版本 | 增量 |
|---|---|
| **v1（本目录）** | 入流量劫持 + orig_dst 桥接 + sk_msg 本地加速 |
| **v2** | + 出流量劫持（仅 server）+ veth/netns 模拟远程 |

## 与其他示例对比

| 示例 | 技术 | 区别 |
|---|---|---|
| [52-sk-lookup-proxy](../52-sk-lookup-proxy) | sk_lookup + bpf_sk_assign | 入站多端口复用单 socket，**入站方向** |
| [29-sockops](../29-sockops) | sockops + sk_msg | 本地流量加速，**无 connect 改写** |
| **本示例** | cgroup/connect4 + sockops | **出站 connect 改写**，service mesh 风格 |
