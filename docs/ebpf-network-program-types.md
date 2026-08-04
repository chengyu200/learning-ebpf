# eBPF 网络程序类型全景分析

> 数据来源:
> - `libbpf/docs/program_types.rst`(官方程序类型表)
> - `libbpf/src/libbpf.c:10072`(`section_defs[]`,ELF section → 程序类型映射)
> - `libbpf/include/uapi/linux/bpf.h`(uapi 定义与 helper 说明)
>
> 原始文档: <https://libbpf.readthedocs.io/en/latest/program_types.html>

依据 libbpf 官方文档与 `libbpf/src/libbpf.c:10072` 的 `section_defs[]`,把"网络相关"的程序类型分为四大类:**数据面(包处理)**、**Socket 级**、**Cgroup 级**、**辅助/控制类**。

---

## 一、网络程序类型总表

### A. 数据面包处理类(沿收发包路径)

| 程序类型 | ELF Section | Attach Type | 内核挂载点 | 典型用途 |
|---|---|---|---|---|
| `BPF_PROG_TYPE_XDP` | `xdp` / `xdp.frags` | `BPF_XDP` | 网卡驱动 RX,skb 创建**之前** | DDoS 防护、LB、防火墙、包丢弃/改写/重定向,最高性能 |
| `BPF_PROG_TYPE_XDP` | `xdp/cpumap` / `xdp.frags/cpumap` | `BPF_XDP_CPUMAP` | CPU map 重定向目标侧 | 把包分发到其它 CPU 后再处理 |
| `BPF_PROG_TYPE_XDP` | `xdp/devmap` / `xdp.frags/devmap` | `BPF_XDP_DEVMAP` | devmap 重定向目标侧 | 转发到另一网卡时的二级处理 |
| `BPF_PROG_TYPE_SCHED_CLS` | `tcx/ingress`、`tc/ingress` | `BPF_TCX_INGRESS` | TC ingress,skb 创建**之后**、路由**之前** | 流量分类、policing、改写、镜像 |
| `BPF_PROG_TYPE_SCHED_CLS` | `tcx/egress`、`tc/egress` | `BPF_TCX_EGRESS` | TC egress,路由**之后**、驱动**之前** | 出向整形、限速、QoS |
| `BPF_PROG_TYPE_SCHED_CLS` | `netkit/primary`、`netkit/peer` | `BPF_NETKIT_PRIMARY/PEER` | netkit(L3 veth)设备两端 | netkit 设备的 L3 包处理 |
| `BPF_PROG_TYPE_SCHED_CLS` | `tc`、`classifier`(legacy) | — | 旧版 clsact qdisc | 已废弃,改用 `tcx/*` |
| `BPF_PROG_TYPE_SCHED_ACT` | `action`(legacy) | — | TC action | 已废弃,改用 `tcx/*` |
| `BPF_PROG_TYPE_NETFILTER` | `netfilter` | `BPF_NETFILTER` | Netfilter 5 个 hook(PREROUTING/INPUT/FORWARD/OUTPUT/POSTROUTING),含 IPv4/v6 与 bridge | 替代 iptables 规则,可做包过滤、改写、NAT、defrag |
| `BPF_PROG_TYPE_LWT_IN` | `lwt_in` | — | 路由查找后、**入栈**本地交付前 | 轻量隧道入向,可改路由 |
| `BPF_PROG_TYPE_LWT_OUT` | `lwt_out` | — | 路由输出后、**L2 封装前** | 轻量隧道出向 |
| `BPF_PROG_TYPE_LWT_XMIT` | `lwt_xmit` | — | 转发路径、**L2 封装前**,可封装 | MPLS/IP6 封装、SRv6 headend |
| `BPF_PROG_TYPE_LWT_SEG6LOCAL` | `lwt_seg6local` | — | SRv6 Segment Routing 本地 segment | SRv6 endpoint 行为(End/End.X/End.DX4…) |
| `BPF_PROG_TYPE_FLOW_DISSECTOR` | `flow_dissector` | `BPF_FLOW_DISSECTOR` | 内核解析包头时(命名空间级) | 自定义协议解析,替代 `skb_flow_dissect` |

### B. Socket 级(面向 socket/连接)

| 程序类型 | ELF Section | Attach Type | 内核挂载点 | 典型用途 |
|---|---|---|---|---|
| `BPF_PROG_TYPE_SOCKET_FILTER` | `socket` | — | socket 收包队列前(`sk_receive_skb`) | 最早期的 BPF,tcpdump 抓包过滤 |
| `BPF_PROG_TYPE_SK_LOOKUP` | `sk_lookup` | `BPF_SK_LOOKUP` | socket 查找时(TCP/UDP 收到包后查找 listening/established socket) | 自定义负载均衡、把包指派给特定 socket(Cilium L4LB) |
| `BPF_PROG_TYPE_SK_MSG` | `sk_msg` | `BPF_SK_MSG_VERDICT` | `tcp_sendmsg` 内、msg 出栈 | sockmap 转发、应用层代理(零拷贝) |
| `BPF_PROG_TYPE_SK_SKB` | `sk_skb/stream_parser` | `BPF_SK_SKB_STREAM_PARSER` | socket 收包,切分流 | sockmap 流解析 |
| `BPF_PROG_TYPE_SK_SKB` | `sk_skb/stream_verdict`、`sk_skb/verdict` | `BPF_SK_SKB_STREAM_VERDICT/VERDICT` | socket 收包,判定转发 | sockmap 把流转发到另一 socket |
| `BPF_PROG_TYPE_SK_REUSEPORT` | `sk_reuseport`、`sk_reuseport/migrate` | `BPF_SK_REUSEPORT_SELECT/SELECT_OR_MIGRATE` | `reuseport` 选择 socket 时 | 自定义 reuseport 选路、连接迁移 |
| `BPF_PROG_TYPE_SOCK_OPS` | `sockops` | `BPF_CGROUP_SOCK_OPS` | TCP 状态机各回调点(建立/RTT/cwnd/重传…) | TCP 调参、拥塞控制、监控、与 sockmap 联动 |
| `BPF_PROG_TYPE_STRUCT_OPS` | `struct_ops` | — | 注册为 TCP 拥塞控制结构体等 | 自定义 TCP CC(如 BBR 变体) |

### C. Cgroup 级(面向进程/容器)

| 程序类型 | ELF Section | Attach Type | 内核挂载点 | 典型用途 |
|---|---|---|---|---|
| `BPF_PROG_TYPE_CGROUP_SKB` | `cgroup_skb/ingress` | `BPF_CGROUP_INET_INGRESS` | 包交付到 cgroup 内 socket 时 | 入向 per-cgroup 防火墙 |
| `BPF_PROG_TYPE_CGROUP_SKB` | `cgroup_skb/egress` | `BPF_CGROUP_INET_EGRESS` | cgroup 内 socket 发包时 | 出向 per-cgroup 防火墙 |
| `BPF_PROG_TYPE_CGROUP_SOCK` | `cgroup/sock`、`cgroup/sock_create` | `BPF_CGROUP_INET_SOCK_CREATE` | socket 创建时 | 审计/限制 socket 创建 |
| `BPF_PROG_TYPE_CGROUP_SOCK` | `cgroup/sock_release` | `BPF_CGROUP_INET_SOCK_RELEASE` | socket 释放时 | 审计 socket 销毁 |
| `BPF_PROG_TYPE_CGROUP_SOCK` | `cgroup/post_bind4`、`cgroup/post_bind6` | `BPF_CGROUP_INET4/6_POST_BIND` | `bind()` 成功后 | 检查/修改 bind 结果 |
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `cgroup/bind4/6` | `BPF_CGROUP_INET4/6_BIND` | `bind()` 调用 | 修改 bind 地址 |
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `cgroup/connect4/6` | `BPF_CGROUP_INET4/6_CONNECT` | `connect()` 调用 | 透明代理、改目的地址(NAT) |
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `cgroup/sendmsg4/6`、`sendmsg_unix` | `BPF_CGROUP_UDP4/6_SENDMSG` | UDP `sendmsg()` | 改 UDP 目的、透明代理 |
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `cgroup/recvmsg4/6`、`recvmsg_unix` | `BPF_CGROUP_UDP4/6_RECVMSG` | UDP `recvmsg()` | 改 UDP 源/对端 |
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `cgroup/connect_unix`、`getpeername*`、`getsockname*` | … | unix connect / getname | unix socket 代理 |
| `BPF_PROG_TYPE_CGROUP_SOCKOPT` | `cgroup/setsockopt` | `BPF_CGROUP_SETSOCKOPT` | `setsockopt()` | 拦截/改写 socket 选项(如强制 `SO_REUSEPORT`) |
| `BPF_PROG_TYPE_CGROUP_SOCKOPT` | `cgroup/getsockopt` | `BPF_CGROUP_GETSOCKOPT` | `getsockopt()` | 改写返回值(如伪装 buffer size) |

### D. 其它(常归入网络)

| 程序类型 | ELF Section | 用途 |
|---|---|---|
| `BPF_PROG_TYPE_LIRC_MODE2` | `lirc_mode2` | 红外遥控解码,严格说非网络 |

---

## 二、网络收发包流程图(含 eBPF 挂载点)

### 1) 接收路径(RX):从网卡到应用

```
                           ┌─────────────────────────────────────────────────┐
   网卡 NIC ──DMA──►       │ ①  驱动 NAPI poll,从 ring buffer 取包            │
                           │     ╔═══════════════════════════════════════╗     │
                           │     ║ [XDP native]  SEC("xdp"/"xdp.frags") ║ ◀── 最早,skb 还没建,可改包/丢/重定向
                           │     ╚═══════════════════════════════════════╝     │
                           │     ② 分配 skb,进入协议栈 netif_receive_skb     │
                           │     ╔═══════════════════════════════════════╗     │
                           │     ║ [TC ingress]  SEC("tcx/ingress")     ║ ◀── skb 已建,路由前;限速/分类/镜像
                           │     ╚═══════════════════════════════════════╝     │
                           │     ③ [flow_dissector] SEC("flow_dissector") ◀── 内核解析包头时调用(按需)
                           │     ④ Netfilter PREROUTING                       │
                           │     ╔═══════════════════════════════════════╗     │
                           │     ║ [Netfilter]   SEC("netfilter")       ║ ◀── NF_INET_PRE_ROUTING
                           │     ╚═══════════════════════════════════════╝     │
                           └────────────────────────┬────────────────────────┘
                                                    │ 路由判断 ip_rcv_finish
                            ┌───────────────────────┴───────────────────────┐
                            ▼ 本地交付                              ▼ 转发
            ┌────────────────────────────────┐      ┌────────────────────────────────────┐
            │ ⑤ Netfilter INPUT              │      │ ⑤' Netfilter FORWARD               │
            │   [Netfilter] NF_INET_LOCAL_IN │      │   [Netfilter] NF_INET_FORWARD      │
            │ ⑥ [cgroup_skb/ingress]         │      │ ⑥' [LWT_XMIT]  SEC("lwt_xmit")     │ ◀─ 转发封装
            │   per-cgroup 入向过滤           │      │     [LWT_OUT]  SEC("lwt_out")      │
            │ ⑦ socket lookup                │      │ ⑦' Netfilter POSTROUTING           │
            │   [sk_lookup] SEC("sk_lookup") │ ◀──  │     [Netfilter] NF_INET_POST_ROUTING
            │   选择 listening socket         │      │ ⑧' [TC egress] SEC("tcx/egress")   │ ◀─ 出向整形
            │   [sk_reuseport]               │      └──────────────────┬─────────────────┘
            │   reuseport 选 socket           │                         ▼
            │ ⑧ [SOCK_OPS] sockops            │                  驱动发送队列 → NIC
            │   TCP 状态回调                   │
            │ ⑨ [SK_SKB] sk_skb/stream_*      │
            │   sockmap 流解析/verdict         │
            │ ⑩ [SOCKET_FILTER] SEC("socket") │ ◀── socket 过滤(tcpdump)
            │ ⑪ 应用 recvmsg()                │
            │   [cgroup/recvmsg4/6] (UDP)     │ ◀── 改 UDP 源地址
            └────────────────────────────────┘
```

### 2) 发送路径(TX):从应用到网卡

```
   应用 send()/sendmsg()
        │
        ▼ ① CGROUP_SOCK_ADDR
        ╔═══════════════════════════════════════╗
        ║ [cgroup/sendmsg4/6] (UDP)             ║ ◀── 改 UDP 目的地址
        ║ [cgroup/connect4/6]   (TCP,首次连接) ║ ◀── 透明代理/改目的
        ╚═══════════════════════════════════════╝
        │ ② sockmap 出向
        ╔═══════════════════════════════════════╗
        ║ [sk_msg]  SEC("sk_msg")               ║ ◀── tcp_sendmsg 内,可重定向到另一 sock
        ╚═══════════════════════════════════════╝
        │ ③ cgroup 出向过滤
        ╔═══════════════════════════════════════╗
        ║ [cgroup_skb/egress] SEC("cgroup_skb/egress") ║ ◀── per-cgroup 出向防火墙
        ╚═══════════════════════════════════════╝
        │ ④ TCP/IP 协议栈
        │   [SOCK_OPS] sockops  ◀── TCP cwnd/RTT/重传等回调
        │   [CGROUP_SOCKOPT] setsockopt/getsockopt 拦截
        │
        ▼ ⑤ Netfilter OUTPUT
        ╔═══════════════════════════════════════╗
        ║ [Netfilter] SEC("netfilter")          ║ ◀── NF_INET_LOCAL_OUT
        ╚═══════════════════════════════════════╝
        │ ⑥ 路由查找
        │   [LWT_IN]  SEC("lwt_in")   ◀── 本机出向路由 encap(可选)
        │
        ▼ ⑦ Netfilter POSTROUTING
        ╔═══════════════════════════════════════╗
        ║ [Netfilter] NF_INET_POST_ROUTING      ║ ◀── SNAT/改写
        ╚═══════════════════════════════════════╝
        │ ⑧ TC egress
        ╔═══════════════════════════════════════╗
        ║ [TC egress] SEC("tcx/egress")         ║ ◀── QoS/限速/镜像
        ║ [LWT_XMIT]  SEC("lwt_xmit")           ║ ◀─  封装 MPLS/IP6
        ║ [LWT_OUT]   SEC("lwt_out")            ║
        ╚═══════════════════════════════════════╝
        ▼
   驱动发送队列 → NIC
```

### 3) 跨层"包生命周期"快照(挂载点相对位置)

```
  RX 侧:    XDP ──► TC ingress ──► [flow_dissector] ──► Netfilter(PRE) ──► 路由
              ↑       ↑                                    ↑
            最早    skb 已建                           iptables 同点
            最高性能  可分类                              可 NAT/过滤

            ──► Netfilter(IN) ──► cgroup_skb/ingress ──► sk_lookup/reuseport ──► SOCK_OPS ──► SK_SKB ──► SOCKET_FILTER ──► 应用

  TX 侧:    应用 ──► cgroup_sock_addr(sendmsg/connect) ──► sk_msg ──► cgroup_skb/egress
            ──► SOCK_OPS/CGROUP_SOCKOPT ──► Netfilter(OUT) ──► 路由 ──► Netfilter(POST)
            ──► TC egress / LWT_*  ──► NIC
```

---

## 三、选型建议

| 场景 | 首选程序类型 | 理由 |
|---|---|---|
| 抗 DDoS、海量丢包、L3 LB | **XDP** | 最早、最快,skb 创建前 |
| 流量分类/限速/QoS、改写 | **TC (tcx/ingress·egress)** | skb 已建,有元数据,双向 |
| 替代 iptables 规则、NAT | **Netfilter** | 与现有 netfilter hook 同点,可 defrag |
| L4 LB(选择 socket) | **sk_lookup** | 在 socket 查找点介入,性能高 |
| 容器/进程级网络策略 | **cgroup_skb + cgroup_sock_addr** | 按 cgroup 粒度,适合 K8s |
| 透明代理(改 connect/sendmsg) | **cgroup_sock_addr (connect/sendmsg)** | 用户的系统调用点 |
| TCP 调优/监控 | **sockops** | 拿到 TCP 全状态事件 |
| 自定义拥塞控制 | **struct_ops** | 注册为 CC 算法 |
| 零拷贝应用代理(sockmap) | **sk_msg + sk_skb + sockops** | 三件套配合 |
| 自定义协议解析 | **flow_dissector** | 命名空间级,影响 flower/hash |
| SRv6 / MPLS 封装 | **lwt_xmit / lwt_seg6local** | 专为轻量隧道设计 |
| 抓包过滤 | **socket_filter** | tcpdump 经典用法 |

---

## 四、几点关键提醒

1. **TC legacy 已废弃**:`tc`、`classifier`、`action` 三个 section 在 `libbpf.c:10099-10101` 标注 deprecated,新代码用 `tcx/ingress`、`tcx/egress`(TCX 模型,支持多程序链式挂载)。
2. **XDP 多挂载点**:`xdp`(主,驱动 native)、`xdp/cpumap`、`xdp/devmap` 是重定向目标侧的二次处理;`.frags` 后缀表示支持多缓冲(multi-buffer,Jumbo Frame)。
3. **Netfilter 程序**(kernel ≥ 6.4,`BPF_PROG_TYPE_NETFILTER`)和 iptables 同 hook,可设置 `BPF_F_NETFILTER_IP_DEFRAG` 做 IP 分片重组(`bpf.h:1338`)。
4. **cgroup_skb 与 socket_filter 区别**:前者按 cgroup 粒度且在 IP 层后,后者按单 socket 粒度(attach 到 socket 本身)。
5. **sockmap 三件套**:`sk_skb`(收向解析+verdict)、`sk_msg`(发向 verdict)、`sockops`(事件),通常配合 `BPF_MAP_TYPE_SOCKMAP` 做零拷贝代理。
6. 仓库示例可参考:`src/20-tc`(TC)、`src/21-xdp`(XDP)、`src/29-sockops`(sockops + sockmap),分别对应三类最常用的网络数据面程序。
