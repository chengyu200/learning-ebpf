# 53-transparent-proxy-v2 — 入流量 + 出流量双向透明劫持

## 概述

v2 在 v1 基础上新增 **出流量劫持**：server 进程的出站连接（如 connect(192.168.99.2:9090)）也被 `cgroup/connect4` 透明改写到 sidecar:15006，sidecar 查原始目的后回源到真正的远程服务。

**关键约束**：出流量劫持仅对 server PID 生效，client 和其他进程的出连接放行。

### 数据流（v2）

```
┌── cgroup: /sys/fs/cgroup/ebpf-proxy-demo/ ──────────────────────┐
│  成员：sidecar + server + client                                  │
│                                                                  │
│  BPF 程序（由 sidecar 加载）：                                     │
│  ① cgroup/connect4  hijack_connect                               │
│     - 入流量分支：dst==127.0.0.1:8080 → 改写 :15006              │
│     - 出流量分支：PID==server_pid 且 dst 非本地 → 改写 :15006   │
│  ② sockops  bpf_sockops_handler（桥接 + SOCKHASH）              │
│  ③ sk_msg   bpf_redir（本地加速）                                │
│                                                                  │
│  ┌───────┐  connect(127.0.0.1:8080)                               │
│  │ Client│ ──────┐  ① 入流量劫持                                  │
│  │(curl) │       ▼                                               │
│  └───────┘  ┌──────────┐  listen :15006                          │
│             │  Sidecar │ ③ 查 conn_map → orig 127.0.0.1:8080    │
│             │ (proxy)  │ ④ connect(127.0.0.1:8080) PID skip     │
│             └──┬───┬───┘                                         │
│      ⑤ 入回源 │   │ ⑤ 出回源                                    │
│                ▼   ▼                                             │
│  ┌──────────┐  ┌──────────┐                                     │
│  │  Server  │  │  Sidecar  │ ← server 出流量被 ① 劫持到 :15006  │
│  │  :8080   │  │  (proxy)  │ ③ 查 conn_map → orig 192.168.99.2  │
│  │          │  │           │ ④ connect(192.168.99.2:9090) PID  │
│  │ GET /out│  │           │    skip                            │
│  │bound    │  └─────┬─────┘                                     │
│  └────┬─────┘        │                                           │
│       │ server connect(192.168.99.2:9090) ① 出流量劫持          │
│       └──────────────┘                                           │
└──────────────────────────────┬───────────────────────────────────┘
                               │ veth pair
                    ┌──────────┴──────────┐
                    │ bpfns netns         │
                    │ 192.168.99.2:9090  │
                    │ external-server    │
                    └─────────────────────┘
```

## v2 相对 v1 的变化

| 组件 | v1 | v2 变化 |
|---|---|---|
| `sidecar.bpf.c` connect4 | 仅匹配 dst==8080 | + 出流量分支：PID==server_pid 且 dst 非本地 → 改写到 127.0.0.1:15006 |
| `sidecar.bpf.c` maps | 3 个 | + `server_pid_map`（ARRAY，存 server PID） |
| `sidecar.c` | 写 sidecar PID | + 写 server PID 到 server_pid_map（从 argv 或 SERVER_PID 环境变量取） |
| `server.c` | 纯 HTTP echo | + GET /outbound 时 connect 外部服务 |
| `external-server.c` | — | 新增：bpfns 内 :9090 echo |
| `Makefile` | 双二进制 | 三二进制 |
| `run-demo.sh` | 一键 | + setup-veth + ip netns exec |

## connect4 出流量分支逻辑

```
hijack_connect(ctx):
  if PID == sidecar_pid: return 1           // 防递归
  if dst == 127.0.0.1:8080:                 // 入流量
      save orig_dst[cookie]; rewrite port → 15006
  elif PID == server_pid:                   // 出流量（仅 server）
      if dst == 127.0.0.1: skip             // 本地连接不劫持
      save orig_dst[cookie]; rewrite ip+port → 127.0.0.1:15006
  else: return 1                            // 其他进程放行
```

## 编译与运行

```bash
# 编译
make -C src/53-transparent-proxy-v2

# 一键演示（需 root + 先建 veth）
sudo ./src/53-transparent-proxy-v2/run-demo.sh

# 或手动分步：
# 1. 建 veth 对
sudo ./scripts/setup-veth.sh create

# 2. 启动 external-server 在 bpfns 内
ip netns exec bpfns ./src/53-transparent-proxy-v2/external-server &

# 3. 启动 server
./src/53-transparent-proxy-v2/server &
SERVER_PID=$!

# 4. 启动 sidecar（传 server PID）
sudo ./src/53-transparent-proxy-v2/sidecar $SERVER_PID &

# 5. 将测试 shell 移入 cgroup
echo $$ | sudo tee /sys/fs/cgroup/ebpf-proxy-demo/cgroup.procs

# 6. 测试
curl http://127.0.0.1:8080/hello       # 入流量
curl http://127.0.0.1:8080/outbound    # 出流量（经 sidecar 到 bpfns）

# 7. 清理
sudo ./scripts/setup-veth.sh delete
```

## 验证点

| # | 测试 | 预期 |
|---|---|---|
| 1 | `curl 127.0.0.1:8080/hello` | 入流量不回归，收到 server 响应 |
| 2 | `curl 127.0.0.1:8080/outbound` | 响应含 external-server 回显 |
| 3 | sidecar 日志 | 出流量劫持记录 `hijack(out): ... 192.168.99.2:9090->127.0.0.1:15006` |
| 4 | client 自身出连接 | 不被劫持（PID ≠ server_pid） |

## 文件结构

```
53-transparent-proxy-v2/
├── Makefile              # 三二进制：sidecar + server + external-server
├── proxy.h               # 共享常量（含 EXT_SERVER_* 定义）
├── sidecar.bpf.c         # 4 程序 + 4 map（+server_pid_map）
├── sidecar.c             # BPF loader + TCP 代理（argv 取 server PID）
├── server.c              # HTTP echo + /outbound 出连接
├── external-server.c     # bpfns 内 :9090 echo
└── run-demo.sh           # 一键演示（含 setup-veth）
```

## 与 v1 对比

| 特性 | v1 | v2 |
|---|---|---|
| 入流量劫持 | ✅ client connect :8080 → sidecar | ✅ 不回归 |
| 出流量劫持 | ❌ | ✅ server connect 外部 → sidecar |
| PID 白名单 | sidecar only | sidecar + server（定向） |
| 外部服务 | 无 | veth+netns 模拟 |
| sk_msg 加速 | ✅ | ✅ 不回归 |
| getpeername4 透明性 | ❌ | ❌（同 v1 限制） |
