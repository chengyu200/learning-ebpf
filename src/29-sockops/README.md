# 29-sockops — 加速本地网络请求转发

用 sockops (`BPF_SOCK_OPS`) + sk_msg (`BPF_SK_MSG_VERDICT`) 程序在本地进程间直接转发 TCP 包，绕过 TCP/IP 协议栈。sockops 程序在连接建立时把 sockhash 填充；sk_msg 程序在发包时查找目标 socket 并 redirect 到其对端 ingress 队列。

## 做什么

- 内核态（两个 BPF 对象，共享一个 `BPF_MAP_TYPE_SOCKHASH`）：
  - `SEC("sockops")` (`bpf_contrack.bpf.c`)：仅在 `PASSIVE/ACTIVE_ESTABLISHED_CB`、且两端都是 `127.0.0.1` 时，以 `{sip,dip,sport,dport,family}` 为 key 调 `bpf_sock_hash_update` 把 socket 写入 sockhash。
  - `SEC("sk_msg")` (`bpf_redirect.bpf.c`)：在 `tcp_sendmsg` 路径上，反向构造 key 查 sockhash，命中则 `bpf_msg_redirect_hash(..., BPF_F_INGRESS)` 把消息直接塞进对端 socket 接收队列，跳过发送方 TCP/IP 栈和 lo 网卡；未命中则 `return SK_PASS` 回退正常 TCP 路径。
- 用户态 (`bpf_contrack.c`)：加载 sockops 并 attach 到根 cgroup；加载 sk_msg 并 attach 到共享的 sockhash；循环读 `trace_pipe` 输出调试日志。

## 教学概念

- sockops + sk_msg + sockhash 三件套：sockops 建立连接跟踪，sk_msg 在发送路径做 verdict，sockhash 是两者的桥梁。
- `bpf_sock_hash_update` / `bpf_msg_redirect_hash` / `BPF_F_INGRESS`。
- sk_msg 的 key 构造：发送方视角的 `remote/local` ↔ 接收方视角的 `local/remote`，二者互为镜像。
- `bpf_sock_ops` / `sk_msg_md` 中 IP 与 `remote_port` 是**网络字节序**，`local_port` 是**主机字节序**（见 `libbpf/include/uapi/linux/bpf.h` 字段注释）。
- **map 复用时序**：`bpf_map__reuse_fd` 必须在 `__load()` **之前**调用，否则 load 时会创建一个新 sockhash，程序内部绑定的就是新 map，reuse 只换了结构体里的 fd 字段，三方不一致导致短路失效（详见下方“踩坑”）。

## 运行

```bash
make -C src/29-sockops
sudo ./src/29-sockops/bpf_contrack
# 另开终端产生本地流量：
curl -s http://127.0.0.1:8080/   # 需先 python3 -m http.server 8080
# 或查看原始 trace：sudo cat /sys/kernel/tracing/trace_pipe
```

> 本程序只处理 `127.0.0.1` 回环流量，**不需要**建 veth 对。

## 观察验证

配套脚本 `observe-sockops.sh` 一键验证短路是否生效：构建 → 起本地 HTTP server → 不挂 BPF 抓基线 → 挂 BPF 再抓 → 读 trace_pipe → 查 sockhash 数量 → 给出 PASS/FAIL 结论。

```bash
sudo ./src/29-sockops/observe-sockops.sh [port]   # 默认 8080
```

预期输出（短路生效）：

```
[3] 基线（不挂 BPF）  HTTP 明文行数: 5      ← 走 lo，tcpdump 抓到
[4] 挂载 BPF         HTTP 明文行数: 0      ← 被旁路，lo 上消失
    >>> new conn: op=5 ... update_err=0    ← sockhash 写入成功
    >>> sk_msg redir: ret=1 ...           ← redirect 命中(SK_PASS=1)
[5] sockhash 数量: 1                       ← map 复用成功
PASS  短路生效
```

trace_pipe 日志解读：

| 日志 | 字段 | 含义 |
|---|---|---|
| `>>> new conn: op=N A->B update_err=E` | `op` | 4=ACTIVE(主动连)、5=PASSIVE(被动连) |
| | `update_err` | 0=写入成功；-17=-EEXIST(重复回调，正常) |
| `>>> sk_msg redir: ret=R lp=X rp=Y` | `ret` | 1=SK_PASS 命中并旁路；0=SK_DROP 未命中回退正常路径 |

也可手动验证：

```bash
# 1. sockhash 应只有 1 个（修复前是 2 个）
sudo bpftool map show | grep -c sockhash
# 2. 挂 BPF 后 lo 上应抓不到 HTTP 明文，只剩握手/FIN
sudo tcpdump -i lo -A 'tcp port 8080'
# 3. TCP 计数器：旁路数据不计入 TcpOutSegs/TcpInSegs
nstat -az TcpOutSegs TcpInSegs
```

## 踩坑：map 复用时序错误

原 loader 用 `bpf_redirect_bpf__open_and_load()` 先 load，再 `bpf_map__reuse_fd()` 复用 ct_skel 的 sockhash。这会导致：

1. load 时 `map->reused=false`（`libbpf.c:5657`），创建 rd_skel 自己的**新 sockhash**，sk_msg 程序在 load 时绑定到这个新 map（BPF 程序的 map 引用在 load 时解析成内核 map 指针，之后不可变）。
2. reuse 只替换 map 结构体里的 fd 字段，**改不了程序内部的 map 绑定**。
3. `attach_sockmap` 用 reuse 后的 fd，把 sk_msg attach 到 ct_skel 的 map，于是 sockops 写入的 socket 会触发 sk_msg。
4. sk_msg 触发后，内部 redirect 查的是 load 时绑定的 rd_skel 新 map（空），查不到 → `SK_DROP` → `return SK_PASS` → 回退正常 TCP 路径 → tcpdump 抓到明文。

**修复**：把 `__open_and_load()` 拆成 `__open()` → `bpf_map__reuse_fd()` → `__load()`，让 reuse 在 load 之前生效。load 时 `map->reused=true`，跳过创建，程序直接绑定 ct_skel 的 sockhash，三方一致。

## 关键提醒

- **先挂 BPF 再发起连接**：sockops 只在连接建立时写 sockhash。若连接在 attach 前已建好，该连接的 socket 不在 map 里，sk_msg 查不到 → 走正常路径。
- **只旁路数据段**：TCP 握手（SYN/SYN-ACK/ACK）和 FIN 仍走 lo，只有后续 `PSH` 数据段可能被旁路。所以 `tcpdump` 上仍会看到连接建立/拆除的包。
