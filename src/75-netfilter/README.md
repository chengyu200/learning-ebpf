# 75-netfilter

用 `BPF_PROG_TYPE_NETFILTER` 在 netfilter 框架（与 iptables/nftables 同层）实现 BPF 防火墙。

## 什么是 BPF Netfilter

`BPF_PROG_TYPE_NETFILTER` 允许 BPF 程序挂载到 Linux netfilter 框架的 5 个 hook 点，与 iptables 规则在同一层运行。内核 6.14+ 引入（`CONFIG_NETFILTER_BPF_LINK=y`）。

### 与 TC/XDP 的对比

| 特性 | TC (clsact) | XDP | veth + TC | **Netfilter** |
|------|------------|-----|-----------|-----------|
| Hook 层 | qdisc | 驱动层 | 虚拟设备对 + TC filter | **netfilter (iptables 层)** |
| 上下文 | `__sk_buff` | `xdp_md` | `__sk_buff` | **`bpf_nf_ctx`** |
| `nf_hook_state` | ❌ | ❌ | ❌ | **✅ (hook/pf/in/out dev)** |
| 包数据访问 | `data`/`data_end` | `data`/`data_end` | `data`/`data_end` | **`bpf_probe_read_kernel` + `BPF_CORE_READ`** |
| 判决值 | `TC_ACT_OK/SHOT` | `XDP_PASS/DROP` | `TC_ACT_OK/SHOT` | **`NF_ACCEPT/DROP`** |
| 多 hook 点 | ingress/egress | RX only | ingress/egress | **5 个 (PRE_ROUTING ~ POST_ROUTING)** |

## Netfilter 5 个 Hook 点

| Hook | 值 | 对应 iptables 链 | 触发时机 |
|------|---|-----------------|---------|
| `NF_INET_PRE_ROUTING` | 0 | PREROUTING | 包到达后、路由前 |
| `NF_INET_LOCAL_IN` | 1 | INPUT | 路由后、到本机的包 |
| `NF_INET_FORWARD` | 2 | FORWARD | 路由后、转发的包 |
| `NF_INET_LOCAL_OUT` | 3 | OUTPUT | 本机发出的包 |
| `NF_INET_POST_ROUTING` | 4 | POSTROUTING | 发出前 |

本示例挂载到 `NF_INET_LOCAL_IN`（IPv4 INPUT 链），过滤进入本机的包。

## 上下文：`struct bpf_nf_ctx`

```c
struct bpf_nf_ctx {
    const struct nf_hook_state *state;  // hook 状态
    struct sk_buff *skb;                // 数据包
};

struct nf_hook_state {
    u8 hook;           // hook 号 (NF_INET_*)
    u8 pf;              // 协议族 (NFPROTO_*)
    struct net_device *in;   // 入接口
    struct net_device *out;  // 出接口
    struct sock *sk;         // 关联的 socket
    struct net *net;         // 网络命名空间
};
```

与 TC 的 `__sk_buff` 不同，netfilter 的上下文是 `bpf_nf_ctx`，包含真实的 `struct sk_buff *`。需要用 `bpf_skb_load_bytes` 读取包数据，用 `BPF_CORE_READ` 读取元数据。

## 做什么

- 挂载到 `NF_INET_LOCAL_IN`（IPv4 INPUT 链）
- **规则 1**：丢弃 ICMP（禁止 ping 本机）
- **规则 2**：丢弃 TCP:8080（禁止访问 8080 端口）
- **规则 3**：允许其他所有流量（包括 SSH:22，不影响远程连接）
- 统计：per-CPU map 按协议分类计数
- 日志：丢弃的包发送到 ringbuf（协议、源 IP、目的 IP、目的端口）

## 运行

```bash
make -C src/75-netfilter
sudo ./src/75-netfilter/netfilter
# 程序每秒打印统计，Ctrl-C 停止
```

## 验证

```bash
# ICMP → 被 DROP
ping -c 1 127.0.0.1
# → 100% packet loss

# TCP:8080 → 被 DROP（先起 server 再连）
nc -l -p 8080 &
nc -w 1 127.0.0.1 8080
# → 无响应（SYN 被 drop）

# TCP:22 → 正常（SSH 不受影响）
nc -w 1 127.0.0.1 22
# → SSH banner（BPF 放行）

# TCP:80 → 正常（非 8080 端口）
nc -w 1 127.0.0.1 80
# → connection refused（但 BPF 不丢弃）
```

### 输出示例

```
BPF netfilter firewall attached to NF_INET_LOCAL_IN (IPv4 INPUT)
  Rule 1: DROP ICMP (ping blocked)
  Rule 2: DROP TCP:8080 (port blocked)
  Rule 3: ACCEPT all other (SSH:22 OK)

proto     pkts    bytes  dropped
──────  ────────  ────────  ────────
TCP         63      3239        0
UDP          0         -        -
ICMP         2         -        3
Other        0         -        -
──────  ────────  ────────  ────────
Total       65      3239        3

[DROP] ICMP  127.0.0.1 → 127.0.0.1
[DROP] TCP   127.0.0.1 → 127.0.0.1:8080
```

> 注：TCP 包数较高是因为 `NF_INET_LOCAL_IN` 拦截所有进入本机的 IPv4 包（包括 SSH、DNS、后台流量等），不仅仅是测试流量。

## 教学概念

| 概念 | 说明 |
|------|------|
| `SEC("netfilter")` | netfilter BPF 程序声明 |
| `bpf_nf_ctx` | 上下文含 `nf_hook_state` + `sk_buff`（非 `__sk_buff`） |
| `bpf_program__attach_netfilter` | attach API，需指定 `pf`/`hooknum`/`priority` |
| `bpf_netfilter_opts` | attach 选项：`pf=NFPROTO_IPV4`, `hooknum=NF_INET_LOCAL_IN`, `priority=0` |
| `bpf_probe_read_kernel` | 从 `skb->data` 读取包数据（netfilter 程序不能使用 `bpf_skb_load_bytes`） |
| `BPF_CORE_READ` | 读取 `sk_buff` 元数据字段（如 `skb->data`, `skb->len`） |
| `NF_INET_LOCAL_IN` | 5 个 hook 点之一，对应 iptables INPUT 链 |
| `NF_ACCEPT(1)` / `NF_DROP(0)` | netfilter 判决值（与 iptables 的 ACCEPT/DROP 相同） |

## 技术细节

### 包数据访问：bpf_probe_read_kernel + BPF_CORE_READ

TC/XDP 程序通过 `ctx->data` / `ctx->data_end` 直接访问包内存（指针 + bounds check）。Netfilter 程序的上下文是 `bpf_nf_ctx`，其中的 `skb` 是真实的 `struct sk_buff *`。

**注意**：`bpf_skb_load_bytes` 在 `BPF_PROG_TYPE_NETFILTER` 上**不可用**（验证器拒绝：`program of this type cannot use helper bpf_skb_load_bytes`）。需要用 `BPF_CORE_READ` 获取 `skb->data` 指针，再用 `bpf_probe_read_kernel` 读取包数据：

```c
/* 1. 获取 skb->data 指针 */
unsigned char *data = BPF_CORE_READ(skb, data);

/* 2. 用 bpf_probe_read_kernel 读 IP 头 */
struct iphdr iph;
bpf_probe_read_kernel(&iph, sizeof(iph), data);

/* 3. 读 TCP 头（offset = ihl * 4） */
struct tcphdr tcp;
bpf_probe_read_kernel(&tcp, sizeof(tcp), data + ihl * 4);
```

在 `NF_INET_LOCAL_IN` hook，`skb->data` 指向网络头（IP 头），所以 offset 0 = IP 头起始。`bpf_probe_read_kernel` 内部使用 `copy_from_kernel_nofault`，安全处理无效地址（返回错误而非崩溃）。

### 元数据访问：BPF_CORE_READ

`struct sk_buff *` 和 `struct nf_hook_state *` 是内核指针，不能直接解引用。用 `BPF_CORE_READ` 安全读取：

```c
__u32 len = BPF_CORE_READ(skb, len);           // 包长度
__u8  hook = BPF_CORE_READ(state, hook);       // hook 号
```

### attach API

```c
LIBBPF_OPTS(bpf_netfilter_opts, opts,
    .pf       = NFPROTO_IPV4,       // 协议族
    .hooknum  = NF_INET_LOCAL_IN,  // hook 点
    .priority = 0,                 // 优先级（多个程序时排序）
);
bpf_program__attach_netfilter(skel->progs.nf_firewall, &opts);
```

`priority` 决定同一 hook 点多个 BPF 程序的执行顺序（值越小越先执行）。与 iptables 规则的顺序类似。

## 文件结构

```
75-netfilter/
├── Makefile           # APP := netfilter
├── netfilter.h          # 共享：统计结构、事件结构
├── netfilter.bpf.c      # BPF 防火墙程序
├── netfilter.c          # 加载器 + 统计打印 + ringbuf 消费
└── README.md
```
