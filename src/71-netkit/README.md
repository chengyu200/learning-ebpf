# 71-netkit

用 `BPF_NETKIT_PRIMARY` 和 `BPF_NETKIT_PEER` 在 netkit 虚拟设备对的两端做包过滤。

## 什么是 Netkit

Netkit 是 Linux 6.7+ 引入的**虚拟网络设备对**（类似 veth pair），专为 BPF 程序设计。它是 TC 的现代替代方案。

### 与 TC/XDP/veth 的对比

| 特性 | TC (clsact) | XDP | veth + TC | **Netkit** |
|------|------------|-----|-----------|-----------|
| 机制 | 挂在已有网卡上 | 挂在驱动层 | 虚拟设备对 + TC filter | **专用虚拟设备对** |
| sk_buff | 有 | 无（原始包） | 有 | **有** |
| L2/L3 模式 | 只有 L2 | 只有 L2 | 只有 L2 | **可选 L2/L3** |
| BPF attach | tc filter | xdp | tc filter | **primary + peer** |
| 容器场景 | 需要额外配置 | 不适用 | veth pair + TC | **原生支持** |

## 设备部署架构

```
┌──────────────────────┐          ┌─────────────────────┐
│    宿主机 netns       │          │   容器 netns (nkns)  │
│                      │          │                      │
│  nk0 (primary)       │◄────────►│  nk1 (peer)          │
│  10.0.0.1            │  netkit  │  10.0.0.2            │
│  primary_filter      │   设备对  │  peer_filter         │
│  host→container 过滤 │          │  container→host 过滤  │
└──────────────────────┘          └─────────────────────┘
```

- **Primary（nk0）在宿主机 netns 中**：`primary_filter` 在 primary 发送时运行，过滤 host→container 流量（容器的 ingress）
- **Peer（nk1）在容器 netns 中**：`peer_filter` 在 peer 发送时运行，过滤 container→host 流量（容器的 egress）

这是 Cilium 的典型部署模型：primary 留在宿主机侧，peer 移入容器 netns。好处是宿主机可以直接管理 BPF 程序，不需要 `setns` 进入容器网络命名空间。

## BPF 程序运行方向

BPF 程序运行在**发送端**的 `netkit_xmit()` 路径——即当设备**发送**包时触发对应端的 BPF 程序：

| BPF 程序 | 触发时机 | 看到的流量方向 | 过滤策略 | 安全角色 |
|----------|---------|--------------|---------|---------|
| `BPF_NETKIT_PRIMARY` | primary 发送时 | host→container | 丢弃 TCP:8080 | 容器 ingress 过滤 |
| `BPF_NETKIT_PEER` | peer 发送时 | container→host | 丢弃 ICMP | 容器 egress 过滤 |

相当于容器的**双向防火墙**：
- **Primary（host 侧）= ingress 过滤**：控制什么可以进入容器
- **Peer（container 侧）= egress 过滤**：控制什么可以离开容器

## 做什么

- 创建 netkit L3 设备对（primary=nk0 在宿主机，peer=nk1 在容器 netns）
- **Primary 端 BPF 程序**（host→container）：丢弃 TCP:8080（禁止宿主机访问容器的 8080 端口）
- **Peer 端 BPF 程序**（container→host）：丢弃 ICMP（禁止容器 ping 宿主机）

## 教学概念

| 概念 | 说明 |
|------|------|
| `SEC("netkit/primary")` | 挂载到 netkit 设备的 primary 端，在 primary 发送时运行 |
| `SEC("netkit/peer")` | 挂载到 netkit 设备的 peer 端，在 peer 发送时运行 |
| `bpf_program__attach_netkit` | libbpf attach API（**两个 attach 都用 primary 的 ifindex**） |
| L3 模式 | `mode l3` — 设备层面不处理 ARP，但 skb 仍包含以太网头 |
| `NETKIT_PASS(0)` / `NETKIT_DROP(2)` | 返回值语义 |
| primary 在宿主机侧 | Cilium 典型部署：primary 留在 host，可直接 attach，不需要 setns |

## 运行

```bash
make -C src/71-netkit
sudo ./src/71-netkit/netkit
# 程序自动创建 netkit 设备对和 netns
# Ctrl-C 停止并自动清理
```

## 验证

```bash
# host→container TCP:8080 → 被 primary 丢弃
nc -w 2 10.0.0.2 8080
# → 无响应（SYN 被 drop）

# container→host ICMP → 被 peer 丢弃
ip netns exec nkns ping -c 1 10.0.0.1
# → 100% packet loss

# host→container TCP 非 8080 → 正常通信（需先在容器中启动 server）
ip netns exec nkns bash -c 'nc -l -p 9000 &'
echo hello | nc -w 2 10.0.0.2 9000
# → 正常

# container→host TCP 非 8080 → 正常通信（需先在宿主机启动 server）
nc -l -p 9000 &
ip netns exec nkns bash -c 'echo hello | nc -w 2 10.0.0.1 9000'
# → 正常
```

### 输出示例

```
  nk0 (primary, ifindex=103, in host) <-> nk1 (peer, ifindex=102, in nkns)

BPF programs attached:
  Primary (nk0 in host): drop TCP:8080 (host → container, container ingress)
  Peer    (nk1 in nkns): drop ICMP (container → host, container egress)

Test:
  nc 10.0.0.2 8080                     → dropped by primary (TCP:8080, host→container)
  ip netns exec nkns ping 10.0.0.1     → dropped by peer (ICMP, container→host)
  ip netns exec nkns nc 10.0.0.1 9000  → passed (non-8080 port)

sec     PRIMARY (host→container)  PEER (container→host)
           pkts    bytes  dropped      pkts    bytes  dropped
──────  ────────────────────────────  ────────────────────────────
1              2      144        1         0        0        0
4              2      144        1         3      266        2
7              5      356        1         6      504        3
```

- PRIMARY: 1 dropped（TCP:8080 SYN 被 drop）
- PEER: 3 dropped（ICMP echo request 被 drop）

## 技术细节

### Netkit L3 模式的 skb 布局

虽然 L3 模式不处理 ARP（设备层面是 L3），但 **skb->data 仍然包含以太网头**（14 字节）。BPF 程序需要跳过以太网头再解析 IP 头：

```c
struct ethhdr *eth = data;
struct iphdr *iph = (void *)(eth + 1);  // 跳过 14 字节以太网头
```

### Netkit 设备对必须跨 netns

同一个 netns 中的 netkit 设备对**无法通信**（ping 失败）。必须将一端移入另一个 netns。

### Primary 留在宿主机侧（Cilium 典型部署）

Cilium 的 netkit 部署模型是 **primary 在 host，peer 在 container/pod**。这样：
- 宿主机可以直接用 `bpf_program__attach_netkit` attach BPF 程序（通过 primary 的 ifindex），**不需要 setns 进入容器 netns**
- primary 端 BPF（`BPF_NETKIT_PRIMARY`）在 primary 发送时运行 = host→container 方向 = 容器 ingress
- peer 端 BPF（`BPF_NETKIT_PEER`）在 peer 发送时运行 = container→host 方向 = 容器 egress

参考：[Cilium netkit blog — Shortcut 4: Introducing netkit](https://isovalent.com/blog/post/cilium-netkit-a-new-container-networking-paradigm-for-the-ai-era/)

### 关键：peer attach 也必须用 primary 的 ifindex

这是 netkit BPF attach 最容易踩坑的地方。内核源码（`drivers/net/netkit.c`）中的 `netkit_dev_fetch()` 函数是所有 BPF attach/detach/query 的入口：

```c
static struct net_device *netkit_dev_fetch(struct net *net, u32 ifindex, u32 which)
{
    dev = __dev_get_by_index(net, ifindex);
    if (dev->netdev_ops != &netkit_netdev_ops)
        return ERR_PTR(-ENXIO);

    nk = netkit_priv(dev);
    if (!nk->primary)              // ← peer 设备 nk->primary == false
        return ERR_PTR(-EACCES);   // ← 返回 -EACCES！

    if (which == BPF_NETKIT_PEER)
        dev = rcu_dereference_rtnl(nk->peer);  // 从 primary 找到 peer
    return dev;
}
```

**所有 BPF 操作都只能通过 primary 设备进行**。无论是 attach primary 程序还是 peer 程序，都必须传入 **primary 设备的 ifindex**。内核通过 `attach_type` 区分：

- `SEC("netkit/primary")` → `attach_type=BPF_NETKIT_PRIMARY` → 在 primary 上 attach
- `SEC("netkit/peer")` → `attach_type=BPF_NETKIT_PEER` → 内核从 primary 找到 peer，在 peer 上 attach

```c
/* 正确：两个 attach 都用 pri_ifindex */
pri_link = bpf_program__attach_netkit(skel->progs.primary_filter, pri_ifindex, NULL);
peer_link = bpf_program__attach_netkit(skel->progs.peer_filter,    pri_ifindex, NULL);

/* 错误：peer attach 用 peer_ifindex → -EACCES */
peer_link = bpf_program__attach_netkit(skel->progs.peer_filter, peer_ifindex, NULL);
```

由于 primary 在宿主机 netns 中，获取 `pri_ifindex` 只需 `if_nametoindex("nk0")`，attach 时也不需要 `setns`。这就是 primary 留在 host 侧的核心优势。
