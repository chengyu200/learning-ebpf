# 53-transparent-proxy-v4 — 端口一致 + PID 排除防回环

## 概述

v4 解决 v3 的端口不一致问题：真实场景中 server 监听 `0.0.0.0:8080`，用户访问 `:8080`，两者端口必须一致。

- **入流量**：`sk_lookup`（netns 级）— 外部 client **无需加入 cgroup**
- **出流量**：`cgroup/connect4`（cgroup 级）— 仅劫持 server PID 的出连接
- **防回环**：sk_lookup 中用 **PID 排除**（`bpf_get_current_pid_tgid()` 匹配 sidecar PID 则跳过）

### v3 的端口不一致问题

v3 中 server 监听 `:9000`，用户访问 `:8080`，靠端口区分防回环。但真实场景中 server 就是监听 `:8080`，端口区分不可行。

### v4 的解决方案

server 监听 `0.0.0.0:8080`（与用户访问端口一致），sk_lookup 拦截 `:8080`，sidecar 回源 `127.0.0.1:8080` 时靠 **PID 排除** 避免再次被拦截。

### 实验性质

`bpf_get_current_pid_tgid()` 在 sk_lookup 中**可用**（bpftool 确认），但 sk_lookup 可能运行在 softirq 上下文，PID 不一定是 sidecar。通过 trace_pipe 观察 `SKIP` 日志是否出现即可判定。

## 数据流

```
外部 client（任意位置，不在 cgroup）
    │
    │ curl 127.0.0.1:8080
    ▼
┌── sk_lookup (netns 级) ──────────────────────────────────┐
│  local_port == 8080？                                     │
│  ├─ PID == sidecar_pid？ → SK_PASS（防回环，放行到 server）│
│  └─ 否 → bpf_sk_assign(sidecar listening socket :15006)  │
└────────────────────┬─────────────────────────────────────┘
                     ▼
┌── cgroup: ebpf-proxy-demo (sidecar + server) ─────────────┐
│                                                             │
│  ┌──────────┐  listen :15006                                │
│  │ Sidecar  │  accept → getpeername → 查 conn_map           │
│  │ (proxy)  │  ├─ 无条目 → 入流量 → connect(127.0.0.1:8080) │
│  │ pthread  │  │   ↑ sk_lookup PID 排除，放行到 server      │
│  │ x N      │  └─ 有条目 → 出流量 → connect(orig_dst)       │
│  └──┬───┬───┘                                               │
│     │   │                                                   │
│     ▼   ▼                                                   │
│  ┌──────────┐  listen 0.0.0.0:8080                          │
│  │  Server  │  纯 HTTP echo（无 BPF）                        │
│  │ :8080    │  GET /outbound → connect(192.168.99.2)        │
│  └────┬─────┘                                               │
│       │ server connect(外部)                                 │
│       ▼                                                     │
│  cgroup/connect4: PID==server_pid？                         │
│  → 保存 orig_dst[cookie]，改写 dst→127.0.0.1:15006         │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼ sidecar 回源到外部
              ┌──────────────┐
              │ bpfns :9090  │
              │ external-srv │
              └──────────────┘
```

## PID 排除防回环

```c
SEC("sk_lookup")
int inbound_lookup(struct bpf_sk_lookup *ctx) {
    if (ctx->local_port != 8080) return SK_PASS;

    __u32 *sidecar_pid = bpf_map_lookup_elem(&sidecar_pid_map, &key);
    if (sidecar_pid) {
        __u32 cur_pid = bpf_get_current_pid_tgid() >> 32;
        if (cur_pid == *sidecar_pid) {
            bpf_printk("sk_lookup: SKIP sidecar pid=%d", cur_pid);
            return SK_PASS;  // sidecar 回源，放行到 server
        }
        bpf_printk("sk_lookup: INTERCEPT pid=%d sidecar=%d",
                   cur_pid, *sidecar_pid);
    }

    // 外部 client → 重定向到 sidecar
    sk = bpf_map_lookup_elem(&sidecar_socks, &key);
    bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return SK_PASS;
}
```

### 判定标准

| trace_pipe 输出 | 含义 | 结果 |
|---|---|---|
| `INTERCEPT pid=<curl_pid>` + `SKIP sidecar pid=<sidecar_pid>` | PID 检测正常 | ✅ 成功 |
| `INTERCEPT pid=0` 或 `INTERCEPT pid=<ksoftirqd>` 无 SKIP | softirq 上下文，PID 不匹配 | ❌ 失败，需备选方案 |

## sk_msg 本地流量加速可观测性

sk_msg 程序通过 `bpf_msg_redirect_hash` 在内核内部将数据从发送方 socket 直接搬到接收方 socket，绕过 qdisc 层。这个过程对用户态完全透明，需要从 BPF 侧观测。

### 两种观测方式

**1. 统计线程（每 5 秒自动输出）**

sidecar 内置独立统计线程，定期读取 `redir_stats` PERCPU_ARRAY 并打印：

```
[sidecar] sk_msg stats: hit=4 miss=1
```

- `hit`：`bpf_msg_redirect_hash` 成功，数据绕过协议栈直接送达
- `miss`：SOCKHASH 未命中（连接建立初期），回退正常 TCP 路径

**2. trace_pipe（详细调试）**

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

输出示例：
```
sk_msg: REDIRECT hit 62663->0     ← 本地段加速生效
sk_msg: REDIRECT hit 36895->0     ← 反向也加速
```

### BPF 侧实现

```c
/* redir_stats PERCPU_ARRAY：[0]=hit, [1]=miss */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} redir_stats SEC(".maps");

SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg) {
    // ...计算 key...
    int ret = bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);

    __u32 stat_key = (ret == 0) ? 0 : 1;
    __u64 *cnt = bpf_map_lookup_elem(&redir_stats, &stat_key);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    if (ret == 0)
        bpf_printk("sk_msg: REDIRECT hit %d->%d", ...);
    return SK_PASS;
}
```

## 端口约定

| 端口 | 用途 |
|---|---|
| `:8080` (VIRTUAL_PORT = SERVER_PORT) | 用户访问 + server 监听（端口一致） |
| `:15006` (SIDECAR_PORT) | sidecar 监听端口 |
| `:9090` (EXT_SERVER_PORT) | bpfns 内外部服务端口 |

## 编译与运行

### 依赖

- libbpf + bpftool（仓库自带，`git submodule update --init --recursive`）
- `libpthread`（glibc 自带，`-lpthread` 已在 Makefile 中配置）
- `iproute2`（`ip`/`tc`，veth+netns 测试需要）

### 一键演示

```bash
# 编译（生成 sidecar + server + external-server）
make -C src/53-transparent-proxy-v4

# 一键演示（需 root，自动建 veth + 启动所有进程 + curl 测试 + 清理）
sudo ./src/53-transparent-proxy-v4/run-demo.sh
```

### 手动分步

```bash
# 1. 建 veth 对（vethbpf0 ↔ bpfns:192.168.99.2）
sudo ./scripts/setup-veth.sh create

# 2. 启动 external-server 在 bpfns 内（模拟远程服务）
ip netns exec bpfns ./src/53-transparent-proxy-v4/external-server &

# 3. 启动 server（监听 0.0.0.0:8080）
./src/53-transparent-proxy-v4/server &
SERVER_PID=$!

# 4. 启动 sidecar（传 server PID 作为参数）
#    sidecar 会自动：
#    - 创建 /sys/fs/cgroup/ebpf-proxy-demo
#    - 把 sidecar PID + server PID 写入 cgroup.procs
#    - 加载 BPF（sk_lookup + connect4 + sockops + sk_msg）
#    - 退出时自动清理 cgroup
sudo ./src/53-transparent-proxy-v4/sidecar $SERVER_PID &

# 5. 测试（curl 无需加入 cgroup！）
curl http://127.0.0.1:8080/hello       # 入流量（sk_lookup 拦截 → sidecar → server:8080）
curl http://127.0.0.1:8080/outbound    # 出流量（server connect 被 connect4 拦截 → sidecar → bpfns）

# 6. 查看 BPF trace（重点观察 SKIP + REDIRECT 日志）
sudo cat /sys/kernel/tracing/trace_pipe

# 7. 观察 sk_msg 加速统计（sidecar 每 5 秒自动输出）
#    [sidecar] sk_msg stats: hit=N miss=N

# 8. 清理
sudo killall sidecar server external-server
sudo ./scripts/setup-veth.sh delete
```

### 启动顺序

必须按以下顺序启动：

```
external-server → server → sidecar <server_pid>
```

## 验证点

| # | 测试 | 预期 |
|---|---|---|
| 1 | `curl 127.0.0.1:8080/hello`（**不加入 cgroup**） | 经 sk_lookup → sidecar → server:8080 |
| 2 | `curl 127.0.0.1:8080/outbound` | server 出连接经 connect4 → sidecar → bpfns |
| 3 | trace_pipe | `INTERCEPT` + `SKIP sidecar`（PID 排除生效） |
| 4 | trace_pipe | `sk_msg: REDIRECT hit`（本地流量加速生效） |
| 5 | sidecar stdout | `sk_msg stats: hit=N miss=N`（每 5 秒统计） |
| 6 | Ctrl-C | 所有进程快速退出 |

## 文件结构

```
53-transparent-proxy-v4/
├── Makefile              # 三二进制（EXTRA_LDFLAGS := -lpthread）
├── proxy.h               # VIRTUAL_PORT = SERVER_PORT = 8080
├── sidecar.bpf.c         # 4 程序 + 7 map（sk_lookup PID 排除 + redir_stats 计数）
├── sidecar.c             # loader + TCP 代理（pthread 并发 + 统计线程 + 回源 :8080）
├── server.c              # HTTP echo on 0.0.0.0:8080 + /outbound
├── external-server.c     # bpfns :9090
├── run-demo.sh           # 一键演示
└── README.md
```

## 版本演进

| 版本 | server 端口 | 防回环机制 | 端口一致 |
|---|---|---|---|
| v1 | :8080 | cgroup/connect4（需 client 在 cgroup） | ✅ 但方式不对 |
| v2 | :8080 | 同 v1 + 出流量 | ✅ 但方式不对 |
| v3 | :9000 | 端口区分（:8080 vs :9000） | ❌ |
| **v4** | **:8080** | **PID 排除**（sk_lookup 检查 sidecar PID） | **✅** |

## 教学概念

| 概念 | 说明 |
|---|---|
| `bpf_get_current_pid_tgid` | 在 sk_lookup 中获取当前进程 PID（实验性） |
| sk_lookup 上下文 | 可能在 softirq 中运行，PID 不一定可靠 |
| PID 排除防回环 | sidecar 回源时 sk_lookup 跳过，避免死循环 |
| 端口一致 | server 监听端口与用户访问端口相同（真实场景需求） |
| `bpf_msg_redirect_hash` | sk_msg 程序中绕过 TCP/IP 协议栈直接重定向数据 |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | per-CPU 计数器，统计 sk_msg redirect hit/miss |
| 可观测性 | 统计线程 + trace_pipe 双重观测本地加速效果 |
