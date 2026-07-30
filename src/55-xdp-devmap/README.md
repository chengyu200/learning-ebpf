# 55-xdp-devmap — XDP DEVMAP 转发 + 镜像

用 `SEC("xdp")` + `SEC("xdp/devmap")` 双程序实现 XDP L3 转发和流量镜像。主程序在入口网卡做转发决策，次级程序在出口网卡 TX 路径上重写 MAC。

## 做什么

- **内核态（两个 XDP 程序，共享 maps）**：
  - `SEC("xdp")` (`xdp_ingress`)：挂在入口网卡（vethext0），解析 IP 头，转发模式匹配目标网段后 `bpf_redirect_map(&forward_map, 0, 0)`；镜像模式用 `bpf_redirect_map(&mirror_map, 0, BPF_F_BROADCAST)` 广播。
  - `SEC("xdp/devmap")` (`xdp_egress`)：挂在 DEVMAP 条目上，在出口网卡（vethint0）TX 路径上运行，重写源/目的 MAC 地址（L3 转发必需），累加统计计数。
- **用户态**：创建网络拓扑（2 对 veth + 3 netns），加载 BPF，填充 DEVMAP `{ifindex, prog_fd}`，attach 主 XDP 程序，Ctrl-C 打印统计。

## 网络拓扑

```
Netns "ext" (外部客户端)       Default ns (路由器 + XDP)        Netns "int" (内部服务)
┌──────────────┐              ┌───────────────────────┐       ┌──────────────┐
│ vethext1     │←─veth pair─→ │ vethext0  10.0.1.1    │       │ vethint1     │
│ 10.0.1.2     │              │  ← SEC("xdp") 主程序  │       │ 10.0.2.2     │
│              │              │                       │       │              │
│              │              │ vethint0  10.0.2.1    │←─veth pair─→│        │
│              │              │  ← xdp/devmap TX 侧  │       │              │
└──────────────┘              └───────────────────────┘       └──────────────┘

路由: ext → 10.0.2.0/24 via 10.0.1.1
      int → 10.0.1.0/24 via 10.0.2.1
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `BPF_MAP_TYPE_DEVMAP` | 存储 `{ifindex, bpf_prog.fd}` 的特殊 map，用于 XDP 重定向 |
| `SEC("xdp/devmap")` | 次级 XDP 程序，在 DEVMAP 重定向后的目标网卡 TX 路径上运行 |
| `bpf_redirect_map()` | 基于 map 的 XDP 重定向（vs `bpf_redirect()` 直接用 ifindex） |
| `BPF_F_BROADCAST` | 广播到 DEVMAP 所有条目（用于镜像） |
| `bpf_devmap_val` | DEVMAP value 结构：`{ifindex, bpf_prog.{fd/id}}` |
| L3 转发 MAC 重写 | XDP L3 转发需在 egress 侧重写 L2 MAC 地址 |
| `XDP_FLAGS_SKB_MODE` | veth 等虚拟网卡需用 SKB 模式（generic XDP） |

## 运行

```bash
make -C src/55-xdp-devmap

# 1. 创建网络环境
sudo ./src/55-xdp-devmap/setup-devmap.sh create

# 2. 转发模式（默认）
sudo ./src/55-xdp-devmap/xdp-devmap
# 另开终端测试：
ip netns exec ext ping 10.0.2.2           # 包经 XDP 转发
ip netns exec int tcpdump -i vethint1 -n  # 看到转发的包

# 3. 镜像模式
sudo ./src/55-xdp-devmap/xdp-devmap -m
# 所有 IPv4 包都广播到 vethint0
ip netns exec int tcpdump -i vethint1 -n  # 看到所有镜像的包

# 4. 清理
sudo ./src/55-xdp-devmap/setup-devmap.sh delete
```

### 参数

| 参数 | 说明 |
|---|---|
| `-m` | 镜像模式（默认转发模式） |
| `-i <ext_if>` | 外部网卡名（默认 vethext0） |
| `-o <int_if>` | 内部网卡名（默认 vethint0） |

## 输出示例

### 转发模式

```
$ sudo ./xdp-devmap
[config] vethint0 src_mac=ae:8b:31:d1:5c:57
[config] DEVMAP[0] → ifindex=60 (vethint0) + egress prog fd=10

FORWARD mode on vethext0 → vethint0. Ctrl-C to stop.
Pkts to 10.0.2.0/24 on vethext0 will be forwarded to vethint0

$ ip netns exec ext ping -c 3 10.0.2.2
64 bytes from 10.0.2.2: icmp_seq=1 ttl=63 time=0.214 ms
64 bytes from 10.0.2.2: icmp_seq=2 ttl=63 time=0.033 ms
64 bytes from 10.0.2.2: icmp_seq=3 ttl=63 time=0.031 ms

=== Stats ===
  forwarded : 3 pkts, 294 bytes
```

### 镜像模式

```
$ sudo ./xdp-devmap -m
MIRROR mode on vethext0 → vethint0. Ctrl-C to stop.
All IPv4 pkts on vethext0 will be broadcast to vethint0

$ ip netns exec int tcpdump -i vethint1 -n
20:19:44 IP 10.0.1.2 > 10.0.2.2: ICMP echo request    ← 镜像
20:19:44 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply      ← 镜像
20:19:45 IP 10.0.1.2 > 10.0.1.1: ICMP echo request    ← 镜像（非转发流量）

=== Stats ===
  mirrored  : 4 pkts, 392 bytes
```

## DEVMAP 工作原理

```
ingress 网卡 (vethext0)                  egress 网卡 (vethint0)
┌──────────────────────┐                ┌───────────────────────┐
│ SEC("xdp")           │  redirect_map  │ SEC("xdp/devmap")     │
│                      │──────────────→ │                       │
│ 1. 解析 IP 头        │  via DEVMAP    │ 1. 重写 src/dst MAC   │
│ 2. 匹配 10.0.2.0/24  │                │ 2. 累加统计计数       │
│ 3. bpf_redirect_map  │                │ 3. return XDP_PASS    │
│    (&forward_map,0,0)│                │    (允许发送)         │
└──────────────────────┘                └───────┬───────────────┘
                                                │ TX
                                                ▼
                                         vethint1 收到包
```

**关键点**：`SEC("xdp/devmap")` 程序不是挂在网卡上的，而是挂在 DEVMAP 条目上的。当 `bpf_redirect_map` 把包重定向到 DEVMAP 条目时，如果该条目设置了 `bpf_prog.fd`，次级程序就在目标网卡的 TX 路径上运行。

## 与其他 XDP 示例的对比

| 示例 | 挂载点 | 动作 | 教学点 |
|---|---|---|---|
| 21-xdp | `SEC("xdp")` | XDP_PASS | 基本框架 |
| 41-xdp-tcpdump | `SEC("xdp")` | XDP_PASS | 五元组解析 |
| 42-xdp-loadbalancer | `SEC("xdp")` | XDP_REDIRECT (`bpf_redirect_peer`) | L4 LB + IP 改写 |
| **55-xdp-devmap** | `SEC("xdp")` + `SEC("xdp/devmap")` | XDP_REDIRECT (`bpf_redirect_map`) | **DEVMAP + 次级程序 + 镜像** |

## 注意事项

1. **镜像 ≠ 复制放行**：`bpf_redirect_map` 是重定向（原包被消费），不是复制。镜像模式下原包不会到达本机协议栈。真正的"复制+放行"镜像需要 TC 的 `bpf_clone_redirect()`。
2. **MAC 重写必须正确**：L3 转发时，egress 侧的 dst MAC 必须是目标网卡的真实 MAC，否则包会被丢弃。本例通过 `ip netns exec` 读取对端 vethint1 的 MAC。
3. **veth 用 SKB 模式**：虚拟网卡不支持 native XDP，必须用 `XDP_FLAGS_SKB_MODE`。
4. **返回路径需要路由**：netns "int" 需要有到 10.0.1.0/24 的返回路由（setup-devmap.sh 已自动配置）。
