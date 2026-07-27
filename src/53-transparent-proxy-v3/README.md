# 53-transparent-proxy-v3 — sk_lookup 入流量 + connect4 出流量双向透明劫持

## 概述

v3 是透明代理示例的最终版本，采用**双钩子架构**解决 v1/v2 的根本缺陷：

- **入流量**：`sk_lookup`（netns 级）— 外部 client **无需加入 cgroup**，curl 即可被透明劫持
- **出流量**：`cgroup/connect4`（cgroup 级）— 仅劫持 server PID 的出连接
- **cgroup 管理**：sidecar 启动时自动将 server PID 加入 cgroup，退出时移出所有成员并清理 cgroup
- **并发连接**：sidecar 用 `pthread` 为每个连接创建独立线程，支持入/出流量并发代理

### v1/v2 的根本问题

v1/v2 用 `cgroup/connect4` 做入流量劫持，但 connect4 挂钩的是 **connect() 发起方**。真实场景中外部 client 不在 cgroup 内，connect4 不会触发。测试时被迫把 curl shell 也塞进 cgroup，不符合真实场景。

### v3 的解决方案

`sk_lookup` 挂载在 **netns**（不是 cgroup），在内核查找 listening socket 时触发，**不关心 connect 发起方在哪个 cgroup**。外部 client 直接 `curl 127.0.0.1:8080` 即可被劫持。

### 防回环

server 改听 `:9000`（非 `:8080`）。sk_lookup 仅拦截 `:8080`，sidecar 回源到 `:9000` 不会再次触发 sk_lookup。

## 数据流

```
外部 client（任意位置，不在 cgroup）
    │
    │ curl 127.0.0.1:8080
    ▼
┌── sk_lookup (netns 级) ──────────────────────────────┐
│  local_port == 8080？                                 │
│  → bpf_sk_assign(sidecar listening socket :15006)    │
│  local_port == 9000/15006？ → SK_PASS（不拦截）       │
└────────────────────┬─────────────────────────────────┘
                     ▼
┌── cgroup: ebpf-proxy-demo (sidecar 启动时加入 server PID) ─┐
│                                                              │
│  ┌──────────┐  listen :15006                                 │
│  │ Sidecar  │  accept → getpeername → 查 conn_map            │
│  │ (proxy)  │  ├─ 无条目 → 入流量 → connect(:9000)           │
│  │ pthread  │  └─ 有条目 → 出流量 → connect(orig_dst)        │
│  │ x N      │  每个连接独立线程处理 pipe_loop                │
│  └──┬───┬───┘                                                │
│     │   │                                                    │
│     ▼   ▼                                                    │
│  ┌──────────┐  listen :9000                                  │
│  │  Server  │  纯 HTTP echo（无 BPF）                         │
│  │ :9000    │  GET /outbound → connect(192.168.99.2)         │
│  └────┬─────┘                                                │
│       │ server connect(外部)                                  │
│       ▼                                                      │
│  cgroup/connect4: PID==server_pid？                          │
│  → 保存 orig_dst[cookie]，改写 dst→127.0.0.1:15006          │
└──────────────────────────────────────────────────────────────┘
                     │
                     ▼ sidecar 回源到外部
              ┌──────────────┐
              │ bpfns :9090  │
              │ external-srv │
              └──────────────┘
```

## cgroup 成员管理

sidecar 负责 cgroup 的完整生命周期：

1. **启动时**：`mkdir /sys/fs/cgroup/ebpf-proxy-demo`，写入自身 PID + server PID 到 `cgroup.procs`
2. **运行时**：connect4 仅拦截 cgroup 内进程（sidecar PID 防递归跳过，server PID 改写出流量，其他进程不在此 cgroup）
3. **退出时**：读取 `cgroup.procs` 把所有成员移回根 cgroup，`rmdir` 删除子 cgroup

> **注意**：client 无需加入 cgroup（入流量由 netns 级 sk_lookup 拦截）。

## sidecar 区分入/出流量

```c
accept(client_fd);
getpeername(client_fd) → {peer_ip, peer_port};
lookup conn_map[{peer_ip, peer_port}];

if (找到 orig_dst) {
    // 出流量：server 的出连接被 connect4 改写到此
    connect(orig_dst);  // sidecar PID，connect4 跳过
} else {
    // 入流量：外部 client 被 sk_lookup 重定向到此
    // 原始目的就是 :9000（sk_lookup 只拦截 :8080）
    connect(127.0.0.1:9000);
}
```

## 并发连接处理

sidecar 用 `pthread` 为每个连接创建独立线程：

```c
while (!exiting) {
    cli_fd = accept(listen_fd, ...);
    /* 查 conn_map 区分入/出流量，建立 upstream 连接 */
    /* 创建 detached 线程处理 pipe_loop */
    pthread_create(&tid, NULL, handle_conn, cctx);
    pthread_detach(tid);
    /* 主线程立即回到 accept，不阻塞 */
}
```

**为何需要并发**：当 server 处理 `/outbound` 请求时，server 会发起出连接（被 connect4 改写到 sidecar:15006）。同时入流量的 HTTP 连接仍在 sidecar 中等待响应。若 sidecar 单线程阻塞在入流量的 `pipe_loop` 上，server 的出连接无法被 accept，导致死锁超时。多线程后入/出流量可并行处理。

线程共享 sidecar 的 PID，connect4 防递归对所有线程生效。

## BPF 程序与 Map

### 4 个 BPF 程序

| # | 程序 | 类型 | 挂载点 | 作用 |
|---|---|---|---|---|
| 1 | `inbound_lookup` | sk_lookup | netns | `:8080` → `bpf_sk_assign` 到 sidecar socket |
| 2 | `hijack_connect` | cgroup/connect4 | cgroup | 仅 server PID 出连接 → 改写到 sidecar |
| 3 | `bpf_sockops_handler` | sockops | cgroup | 桥接 cookie→conn_key + 填充 SOCKHASH |
| 4 | `bpf_redir` | sk_msg | SOCKHASH | 本地流量加速 |

### 6 个 Map

| # | Map | 类型 | 用途 |
|---|---|---|---|
| 1 | `sidecar_socks` | SOCKMAP | 存 sidecar listening socket fd，供 sk_lookup 用 |
| 2 | `sidecar_pid_map` | ARRAY | 防递归 |
| 3 | `server_pid_map` | ARRAY | 出流量劫持仅对 server PID |
| 4 | `orig_dst_map` | HASH | cookie → 原始目的（仅出流量） |
| 5 | `conn_map` | HASH | 发起方源 {ip,port} → 原始目的 |
| 6 | `sock_ops_map` | SOCKHASH | sk_msg redirect |

## 端口约定

| 端口 | 用途 |
|---|---|
| `:8080` (VIRTUAL_PORT) | 外部 client 访问的虚拟端口（sk_lookup 拦截） |
| `:9000` (SERVER_PORT) | server 实际监听端口（sidecar 回源到此，sk_lookup 不拦截） |
| `:15006` (SIDECAR_PORT) | sidecar 监听端口 |
| `:9090` (EXT_SERVER_PORT) | bpfns 内外部服务端口 |

## 编译与运行

### 依赖

- libbpf + bpftool（仓库自带，`git submodule update --init --recursive`）
- `libpthread`（glibc 自带，链接时需 `-lpthread`，已在 Makefile 中配置）
- `iproute2`（`ip`/`tc`，veth+netns 测试需要）

### 一键演示

```bash
# 编译（生成 sidecar + server + external-server 三个二进制）
make -C src/53-transparent-proxy-v3

# 一键演示（需 root，自动建 veth + 启动所有进程 + curl 测试 + 清理）
sudo ./src/53-transparent-proxy-v3/run-demo.sh
```

### 手动分步

```bash
# 1. 建 veth 对（vethbpf0 ↔ bpfns:192.168.99.2）
sudo ./scripts/setup-veth.sh create

# 2. 启动 external-server 在 bpfns 内（模拟远程服务）
ip netns exec bpfns ./src/53-transparent-proxy-v3/external-server &

# 3. 启动 server（监听 :9000）
./src/53-transparent-proxy-v3/server &
SERVER_PID=$!

# 4. 启动 sidecar（传 server PID 作为参数）
#    sidecar 会自动：
#    - 创建 /sys/fs/cgroup/ebpf-proxy-demo
#    - 把 sidecar PID + server PID 写入 cgroup.procs
#    - 加载 BPF（sk_lookup + connect4 + sockops + sk_msg）
#    - 退出时自动清理 cgroup
sudo ./src/53-transparent-proxy-v3/sidecar $SERVER_PID &

# 5. 测试（curl 无需加入 cgroup！）
curl http://127.0.0.1:8080/hello       # 入流量（sk_lookup 拦截 → sidecar → server:9000）
curl http://127.0.0.1:8080/outbound    # 出流量（server connect 被 connect4 拦截 → sidecar → bpfns）
curl http://127.0.0.1:9000/direct      # 直连 server（sk_lookup 不拦截 :9000）

# 6. 查看 BPF trace
sudo cat /sys/kernel/tracing/trace_pipe

# 7. 清理
sudo killall sidecar server external-server
sudo ./scripts/setup-veth.sh delete
```

### 启动顺序

必须按以下顺序启动，否则 sidecar 无法找到 server PID：

```
external-server → server → sidecar <server_pid>
```

sidecar 退出时会自动清理 cgroup 并移出所有成员。若异常退出残留 cgroup：

```bash
# 手动清理残留 cgroup
for pid in $(cat /sys/fs/cgroup/ebpf-proxy-demo/cgroup.procs); do
    echo $pid > /sys/fs/cgroup/cgroup.procs
done
rmdir /sys/fs/cgroup/ebpf-proxy-demo
```

## 验证点

| # | 测试 | 预期 |
|---|---|---|
| 1 | `curl 127.0.0.1:8080/hello`（**不加入 cgroup**） | 经 sk_lookup → sidecar → server:9000 |
| 2 | `curl 127.0.0.1:8080/outbound` | server 出连接经 connect4 → sidecar → bpfns |
| 3 | `curl 127.0.0.1:9000/direct` | 直连 server，不劫持 |
| 4 | sidecar 日志 | 入流量: `inbound → :9000`；出流量: `outbound → orig_dst` |
| 5 | sidecar 日志 | `server_pid=XXX added to cgroup` |
| 6 | BPF trace | `sk_lookup: :8080->sidecar` + `hijack(out): pid=<server_pid>` |
| 7 | Ctrl-C | 所有进程快速退出（sigaction 修复，<10ms） |
| 8 | sidecar 退出后 | `ebpf-proxy-demo` cgroup 自动删除 |

## TC 方案对比分析

### 为什么 v3 选 sk_lookup 而非 TC？

TC ingress 也能实现入流量劫持（`bpf_sk_assign` 在 `sched_cls` 程序类型中可用），但复杂度显著更高：

| 维度 | sk_lookup | TC ingress |
|---|---|---|
| **工作层** | socket 查找层（L4） | 包层（L2-L4） |
| **触发时机** | 内核查找 listening socket 时 | 每个包到达网卡时 |
| **需解析头部** | 否（ctx 直接含五元组） | **是**（手动解析 ethhdr→iphdr→tcphdr） |
| **TCP 状态机** | 不需处理（只对新连接触发） | **需自行识别 SYN 包** |
| **bpf_sk_assign** | ✅ 直接用 | ✅ 可用，但需先 `bpf_sk_lookup_tcp` |
| **挂载方式** | `bpf_program__attach_netns` | `bpf_tc_hook_create` + `bpf_tc_attach` |
| **本机回环** | ✅ 对 lo 上的 :8080 生效 | ⚠️ lo 的 TC 行为需验证 |
| **跨 netns** | ❌ 仅单个 netns | ✅ 可在 veth 端拦截跨 netns 流量 |
| **代码量** | ~30 行 BPF | ~80-100 行 BPF |
| **适用场景** | 同 netns 入流量劫持 | 跨 netns / 网卡级流量劫持 |

### TC 方案的核心挑战

1. **必须解析数据包头部**：TC 程序工作在包层，需手动解析 ethhdr→iphdr→tcphdr 并做边界检查
2. **需识别 SYN 包**：只对 TCP SYN（新连接第一个包）做 `bpf_sk_assign`，否则每个包都触发
3. **lo 接口行为不确定**：本机回环流量走 `lo`，某些内核配置下 `lo` 的 clsact qdisc 行为与物理网卡不同
4. **orig_dst 恢复更复杂**：TC 层改写后，sidecar 需通过 map 查找恢复原始目的

### TC 方案的适用场景

| 场景 | 推荐方案 |
|---|---|
| 同 netns 入流量劫持（本 demo） | **sk_lookup** |
| 跨 netns 流量劫持（Pod 间） | **TC** |
| 网卡级透明代理（物理网卡入口） | **TC/XDP** |
| 容器内出流量劫持 | **cgroup/connect4** |

### TC 方案伪代码（仅参考）

```c
SEC("tc")
int tc_inbound(struct __sk_buff *skb) {
    /* 1. 解析 ethhdr → iphdr → tcphdr（含边界检查） */
    /* 2. 仅处理 TCP SYN 包（tcp->syn && !tcp->ack） */
    /* 3. 检查 dst_port == 8080 */
    /* 4. bpf_sk_lookup_tcp 找 sidecar listening socket */
    /* 5. bpf_sk_assign(ctx, sk, 0) */
    /* 6. bpf_sk_release(sk) */
    return TC_ACT_OK;
}
```

## 文件结构

```
53-transparent-proxy-v3/
├── Makefile              # 三二进制（EXTRA_LDFLAGS := -lpthread）
├── proxy.h               # VIRTUAL_PORT=8080, SERVER_PORT=9000
├── sidecar.bpf.c         # 4 程序 + 6 map（sk_lookup + connect4 + sockops + sk_msg）
├── sidecar.c             # loader + TCP 代理（pthread 并发 + cgroup 管理 + sigaction）
├── server.c              # HTTP echo on :9000 + /outbound 出连接
├── external-server.c     # bpfns :9090（模拟远程服务）
├── run-demo.sh           # 一键演示（无需 echo $$ > cgroup.procs）
└── README.md             # 含 TC vs sk_lookup 对比分析
```

## 版本演进

| 版本 | 入流量 | 出流量 | cgroup 成员 | 信号修复 | 并发 | cgroup 管理 |
|---|---|---|---|---|---|---|
| v1 | cgroup/connect4（需 client 在 cgroup） | ❌ | sidecar+server+client | ❌ | 单线程 | 手动 |
| v2 | 同 v1 | cgroup/connect4（server PID） | 同 v1 | ❌ | 单线程 | 手动 |
| **v3** | **sk_lookup（netns，client 无需 cgroup）** | 同 v2 | **sidecar 自动加入 server** | ✅ | **pthread** | **sidecar 自动** |

### v3 关键修复

1. **server 加入 cgroup**：sidecar 启动时把 server PID 写入 `cgroup.procs`，否则 connect4 无法拦截 server 出连接
2. **pthread 并发**：每个连接独立线程处理，避免入流量 pipe_loop 阻塞导致出流量 accept 超时
3. **sigaction 信号处理**：`sa_flags = 0` 不设 SA_RESTART，确保 Ctrl-C 能中断 accept/select
4. **cgroup 自动清理**：退出时读取所有成员移回根 cgroup，rmdir 删除子 cgroup

## 教学概念

| 概念 | 说明 |
|---|---|
| `BPF_PROG_TYPE_SK_LOOKUP` | netns 级入站 socket 查找劫持 |
| `bpf_sk_assign` | 将入站连接分配给指定 socket |
| `bpf_program__attach_netns` | 挂载 sk_lookup 到网络命名空间 |
| `BPF_MAP_TYPE_SOCKMAP` | 存储 listening socket 引用 |
| `cgroup/connect4` | cgroup 级出站 connect() 改写 |
| `bpf_get_socket_cookie` | 跨钩子 socket 标识 |
| `sockops` + `sk_msg` | 本地流量加速 |
| `sigaction` vs `signal` | SA_RESTART 对 accept/select 的影响 |
| `pthread` 并发代理 | 每连接独立线程，避免入/出流量互相阻塞 |
| cgroup 成员管理 | sidecar 自动加入/移出 server PID |
