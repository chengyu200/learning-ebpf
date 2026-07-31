# 55-xdp-devmap — XDP DEVMAP 转发 + 镜像

用 `SEC("xdp")` + `SEC("xdp/devmap")` 双程序实现 XDP L3 转发和流量镜像。主程序在入口网卡做转发决策，次级程序在出口网卡 TX 路径上重写 MAC。

## 做什么

- **内核态（两个 XDP 程序，共享 maps）**：
  - `SEC("xdp")` (`xdp_ingress`)：挂在入口网卡（vethext0），解析 IP 头，转发模式匹配目标网段后 `bpf_redirect_map(&forward_map, 0, 0)`；镜像模式用 `bpf_redirect_map(&mirror_map, 0, BPF_F_BROADCAST)` 广播。
  - `SEC("xdp/devmap")` (`xdp_egress`)：挂在 DEVMAP 条目上，在出口网卡（vethint0）TX 路径上运行，重写源/目的 MAC 地址（L3 转发必需），累加统计计数。
- **用户态**：创建网络拓扑（2 对 veth + 3 netns），加载 BPF，填充 DEVMAP `{ifindex, prog_fd}`，attach 主 XDP 程序，Ctrl-C 打印统计。

> 转发模式下，只匹配 `10.0.2.0/24`网段，其他网段不进行转发，转发后， 就绕过了内核协议层面。
> 镜像模式下，到达 vethext0的所有网络包都会向 mirror_map 中所有接口进行广播，如果 mirror_map中包含了 vethext0，则会跳过这个接口。

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
# 终端1
ip netns exec int tcpdump -i vethint1 -n  # 看到转发的包
# 终端2
ip netns exec ext ping 10.0.2.2           # 包经 XDP 转发

结果：如果不打开xdp-devmap程序，终端2就无法ping通。

# 3. 镜像模式
sudo ./src/55-xdp-devmap/xdp-devmap -m
# 所有 IPv4 包都广播到 vethint0

# 终端1: ping vethext0,
ip netns exec ext ping 10.0.1.1
# 终端2: 发现所有包都转发到了vethint0，所以通过下面命令，可以看到ICMP echo request，但是没有ICMP echo reply。
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

### 转发模式 net.ipv4.ip_forward=0
设置net.ipv4.ip_forward的值为0
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# sysctl  -w net.ipv4.ip_forward=0
net.ipv4.ip_forward = 0
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 0
```

**终端1：启动 xdp-devmap，默认转发模式**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ./xdp-devmap 
[config] vethint0 src_mac=ae:8b:31:d1:5c:57
[config] DEVMAP[0] → ifindex=78 (vethint0) + egress prog fd=10

FORWARD mode on vethext0 → vethint0. Ctrl-C to stop.
Pkts to 10.0.2.0/24 on vethext0 will be forwarded to vethint0
Test: ip netns exec ext ping 10.0.2.2
      ip netns exec int tcpdump -i vethint1 -n
```

**终端2: 开启tcpdump观察**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec int tcpdump -i vethint1 -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on vethint1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
// ping 10.0.2.2 -c 3
15:20:09.284523 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 38628, seq 1, length 64
15:20:09.284572 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 38628, seq 1, length 64
15:20:10.372137 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 38628, seq 2, length 64
15:20:10.372173 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 38628, seq 2, length 64
15:20:11.462493 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 38628, seq 3, length 64
15:20:11.462535 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 38628, seq 3, length 64

//ping 10.0.1.1 -c 3
```
**终端3：ping 10.0.2.2 -c 3**

```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec ext ping 10.0.2.2 -c 3
PING 10.0.2.2 (10.0.2.2) 56(84) bytes of data.

--- 10.0.2.2 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2010ms
```

**终端3：ping 10.0.1.1 -c 3**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec ext ping 10.0.1.1 -c 3
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=64 time=0.120 ms
64 bytes from 10.0.1.1: icmp_seq=2 ttl=64 time=0.059 ms
64 bytes from 10.0.1.1: icmp_seq=3 ttl=64 time=0.071 ms

--- 10.0.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1998ms
rtt min/avg/max/mdev = 0.059/0.083/0.120/0.026 ms

```
**终端1:**

```
^C
=== Stats ===
  forwarded : 3 pkts, 294 bytes
XDP detached from vethext0
```

解释：
ping 10.0.2.2 -c 3 时，tcpdump可以看到包，说明转发生效(只转发10.0.2.0/24网段)，而ping无法收到回包，是因为 ip_forward的值为0。
ping 10.0.1.1 -c 3时，tcpdump无法看到包，说明该包并没有转发 (只转发10.0.2.0/24网段)，ping可以收到回包，是因为该包走了内核协议栈。

### 转发模式 net.ipv4.ip_forward=1

设置net.ipv4.ip_forward的值为1
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# sysctl  -w net.ipv4.ip_forward=1
net.ipv4.ip_forward = 1
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 1
```

**终端1：启动 xdp-devmap，默认转发模式**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ./xdp-devmap 
[config] vethint0 src_mac=ae:8b:31:d1:5c:57
[config] DEVMAP[0] → ifindex=78 (vethint0) + egress prog fd=10

FORWARD mode on vethext0 → vethint0. Ctrl-C to stop.
Pkts to 10.0.2.0/24 on vethext0 will be forwarded to vethint0
Test: ip netns exec ext ping 10.0.2.2
      ip netns exec int tcpdump -i vethint1 -n


```

**终端2: 开启tcpdump观察**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec int tcpdump -i vethint1 -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on vethint1, link-type EN10MB (Ethernet), snapshot length 262144 bytes

//ping 10.0.2.2 -c 3
16:30:21.195221 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 39275, seq 1, length 64
16:30:21.195333 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 39275, seq 1, length 64
16:30:22.279545 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 39275, seq 2, length 64
16:30:22.279572 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 39275, seq 2, length 64
16:30:23.361970 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 39275, seq 3, length 64
16:30:23.362008 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 39275, seq 3, length 64

//ping 10.0.1.1 -c 3
```
**终端3：ping 10.0.2.2 -c 3**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec ext ping 10.0.2.2 -c 3
PING 10.0.2.2 (10.0.2.2) 56(84) bytes of data.
64 bytes from 10.0.2.2: icmp_seq=1 ttl=63 time=0.221 ms
64 bytes from 10.0.2.2: icmp_seq=2 ttl=63 time=0.085 ms
64 bytes from 10.0.2.2: icmp_seq=3 ttl=63 time=0.119 ms

--- 10.0.2.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2000ms
rtt min/avg/max/mdev = 0.085/0.141/0.221/0.057 ms
```

**终端3：ping 10.0.1.1 -c 3**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec ext ping 10.0.1.1 -c 3
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=64 time=0.080 ms
64 bytes from 10.0.1.1: icmp_seq=2 ttl=64 time=0.085 ms
64 bytes from 10.0.1.1: icmp_seq=3 ttl=64 time=0.060 ms

--- 10.0.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 0.060/0.075/0.085/0.010 ms
```

**终端1:**
```
^C
=== Stats ===
  forwarded : 3 pkts, 294 bytes
XDP detached from vethext0
```
解释：
ping 10.0.2.2 -c 3 时，tcpdump可以看到包，说明转发生效 (只转发10.0.2.0/24网段)，而ping可以收到回包，是因为 ip_forward的值为1。
ping 10.0.1.1 -c 3时，tcpdump无法看到包，说明该包并没有转发 (只转发10.0.2.0/24网段)，ping可以收到回包，是因为该包走了内核协议栈。

### 镜像模式 net.ipv4.ip_forward=0

设置net.ipv4.ip_forward的值为0
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# sysctl  -w net.ipv4.ip_forward=0
net.ipv4.ip_forward = 0
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 0
```
**终端1：启动 xdp-devmap，-m为镜像模式**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ./xdp-devmap -m
[config] vethint0 src_mac=ae:8b:31:d1:5c:57
[config] DEVMAP[0] → ifindex=78 (vethint0) + egress prog fd=10

MIRROR mode on vethext0 → vethint0. Ctrl-C to stop.
All IPv4 pkts on vethext0 will be broadcast to vethint0
Test: ip netns exec ext ping 10.0.2.2
      ip netns exec int tcpdump -i vethint1 -n
```

**终端2: 开启tcpdump观察**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec int tcpdump -i vethint1 -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode

//ping 10.0.2.2 -c 3
listening on vethint1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
16:36:53.069146 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 39387, seq 1, length 64
16:36:53.069193 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 39387, seq 1, length 64
16:36:54.155939 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 39387, seq 2, length 64
16:36:54.155988 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 39387, seq 2, length 64
16:36:55.243418 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 39387, seq 3, length 64
16:36:55.243437 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 39387, seq 3, length 64




//ping 10.0.1.1 -c 3
16:37:48.820463 IP 10.0.1.2 > 10.0.1.1: ICMP echo request, id 39399, seq 1, length 64
16:37:49.913477 IP 10.0.1.2 > 10.0.1.1: ICMP echo request, id 39399, seq 2, length 64
16:37:51.007538 IP 10.0.1.2 > 10.0.1.1: ICMP echo request, id 39399, seq 3, length 64

```

**终端3：ping 10.0.2.2 -c 3**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec ext ping 10.0.2.2 -c 3
PING 10.0.2.2 (10.0.2.2) 56(84) bytes of data.

--- 10.0.2.2 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2007ms
```

**终端3：ping 10.0.1.1 -c 3**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec ext ping 10.0.1.1 -c 3
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.

--- 10.0.1.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2019ms


```

**终端1:**
```

^C
=== Stats ===
  mirrored  : 6 pkts, 588 bytes
XDP detached from vethext0
```
解释：
镜像模式下 ping 10.0.2.2 -c 3 收不到回包时因为 ip_forward为0，禁止了转发，但是tcpdump可以看到。
镜像模式下 ping 10.0.1.1 -c 3 收不到回包是因为镜像后， 包被发到了其他网口（map里没有接收网络口），所以tcpdump是可以看到。


### 镜像模式 net.ipv4.ip_forward=1

设置net.ipv4.ip_forward的值为0
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# sysctl  -w net.ipv4.ip_forward=1
net.ipv4.ip_forward = 1
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 1
```

**终端1：启动 xdp-devmap，-m为镜像模式**

```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ./xdp-devmap -m
[config] vethint0 src_mac=ae:8b:31:d1:5c:57
[config] DEVMAP[0] → ifindex=78 (vethint0) + egress prog fd=10

MIRROR mode on vethext0 → vethint0. Ctrl-C to stop.
All IPv4 pkts on vethext0 will be broadcast to vethint0
Test: ip netns exec ext ping 10.0.2.2
      ip netns exec int tcpdump -i vethint1 -n

```

**终端2: 开启tcpdump观察**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec int tcpdump -i vethint1 -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on vethint1, link-type EN10MB (Ethernet), snapshot length 262144 bytes


//ping 10.0.2.2 -c 3
16:40:19.157606 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 39567, seq 1, length 64
16:40:19.157631 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 39567, seq 1, length 64
16:40:20.239845 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 39567, seq 2, length 64
16:40:20.239872 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 39567, seq 2, length 64
16:40:21.323951 IP 10.0.1.2 > 10.0.2.2: ICMP echo request, id 39567, seq 3, length 64
16:40:21.323972 IP 10.0.2.2 > 10.0.1.2: ICMP echo reply, id 39567, seq 3, length 64



//ping 10.0.1.1 -c 3
16:40:46.711037 IP 10.0.1.2 > 10.0.1.1: ICMP echo request, id 39577, seq 1, length 64
16:40:47.800005 IP 10.0.1.2 > 10.0.1.1: ICMP echo request, id 39577, seq 2, length 64
16:40:48.891121 IP 10.0.1.2 > 10.0.1.1: ICMP echo request, id 39577, seq 3, length 64
```

**终端3：ping 10.0.2.2 -c 3**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec ext ping 10.0.2.2 -c 3
PING 10.0.2.2 (10.0.2.2) 56(84) bytes of data.
64 bytes from 10.0.2.2: icmp_seq=1 ttl=63 time=0.091 ms
64 bytes from 10.0.2.2: icmp_seq=2 ttl=63 time=0.083 ms
64 bytes from 10.0.2.2: icmp_seq=3 ttl=63 time=0.064 ms

--- 10.0.2.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2000ms
rtt min/avg/max/mdev = 0.064/0.079/0.091/0.011 ms
```

**终端3：ping 10.0.1.1 -c 3**
```
root@ubuntu2604:~/work/learning-ebpf/src/55-xdp-devmap# ip netns exec ext ping 10.0.1.1 -c 3
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.

--- 10.0.1.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2014ms

```

**终端1:**
```
^C
=== Stats ===
  mirrored  : 6 pkts, 588 bytes
XDP detached from vethext0
```
解释：
镜像模式下 ping 10.0.2.2 -c 3 因为包被广播到了其他网口，所以tcpdump可以看到，ping 可以收到回包，是因为 ip_forward为1。
镜像模式下 ping 10.0.1.1 -c 3 收不到回包是因为镜像后，包被发到了其他网口 （map里没有接收网络口），但是tcpdump是可以看到。 

### 结论
转发模式下：包转发到指定的网络接口，由key指定，包就会绕过内核协议栈来处理。
镜像模式后：包会发往map中所有的网络接口，如果设置了 BPF_F_EXCLUDE_INGRESS ，则会排出ingress 网络接口。


## DEVMAP 工作原理

```
ingress 网卡 (vethext0)                  egress 网卡 (vethint0)
┌──────────────────────┐                ┌───────────────────────┐
│ SEC("xdp")           │  redirect_map  │ SEC("xdp/devmap")     │
│                      │──────────────→ │                       │
│ 1. 解析 IP 头         │  via DEVMAP    │ 1. 重写 src/dst MAC   │
│ 2. 匹配 10.0.2.0/24   │                │ 2. 累加统计计数       │
│ 3. bpf_redirect_map  │                │ 3. return XDP_PASS    │
│    (&forward_map,0,0)│                │    (允许发送)         │
└──────────────────────┘                └───────┬───────────────┘
                                                │ TX
                                                ▼
                                         vethint1 收到包
```

**关键点：`SEC("xdp/devmap")` 程序不是挂在网卡上的，而是挂在 DEVMAP 条目上的**。当 `bpf_redirect_map` 把包重定向到 DEVMAP 条目时，如果该条目设置了 `bpf_prog.fd`，次级程序就在目标网卡的 TX 路径上运行。

## 与其他 XDP 示例的对比

| 示例 | 挂载点 | 动作 | 教学点 |
|---|---|---|---|
| 21-xdp | `SEC("xdp")` | XDP_PASS | 基本框架 |
| 41-xdp-tcpdump | `SEC("xdp")` | XDP_PASS | 五元组解析 |
| 42-xdp-loadbalancer | `SEC("xdp")` | XDP_REDIRECT (`bpf_redirect_peer`) | L4 LB + IP 改写 |
| **55-xdp-devmap** | `SEC("xdp")` + `SEC("xdp/devmap")` | XDP_REDIRECT (`bpf_redirect_map`) | **DEVMAP + 次级程序 + 镜像** |

## `ip_forward` 对 XDP 转发的影响详解

`ip_forward` 控制内核协议栈是否能在不同网卡间路由包。默认 ns 有两个网卡（vethext0 + vethint0），当包需要从一个网卡进、另一个网卡出时，必须 `ip_forward=1`。

### 两条独立的转发路径

```
                    vethext0 RX (入口)
                    │
          ┌─────────┴─────────┐
          │                   │
     XDP 快速路径          内核慢速路径
     (BPF 程序)          (ip_forward 控制)
          │                   │
    bpf_redirect_map     路由查找 → ip_forward()
          │                   │
          ▼                   ▼
    vethint0 TX         vethint0 TX
          │                   │
          └─────────┬─────────┘
                    ▼
              vethint1 RX (收到包)
```

XDP 在内核协议栈之前运行。如果 XDP 返回 `XDP_REDIRECT`，包被 XDP 消费（普通 redirect）或克隆（BROADCAST），内核栈是否还能看到取决于模式。

### 各场景详解

**场景 1：转发模式 + `ip_forward=0`**

```
请求路径（去程）:
ext → vethext0 RX → XDP 匹配 10.0.2.0/24
  → bpf_redirect_map (普通 redirect, 原包被消费)
  → vethint0 TX → vethint1 RX → 内核处理 → 回复 echo reply ✓

回复路径（回程）:
vethint1 TX → vethint0 RX → 内核路由查找
  → 目标 10.0.1.2, 需要从 vethint0 → vethext0 (跨网卡)
  → ip_forward=0 → 拒绝转发 ✗
  → echo reply 丢失 → ping 100% 丢包
```

XDP 转发成功把请求送到 vethint1，但回复从 vethint0 回到 vethext0 需要内核跨网卡路由，`ip_forward=0` 阻止了这一步。

**场景 2：转发模式 + `ip_forward=1`**

```
请求路径（去程）:
ext → vethext0 RX → XDP redirect → vethint0 → vethint1 → 回复 ✓

回复路径（回程）:
vethint1 TX → vethint0 RX → 内核路由查找
  → 目标 10.0.1.2, 从 vethint0 → vethext0 (跨网卡)
  → ip_forward=1 → 允许转发 ✓
  → vethext0 TX → vethext1 RX → ext 收到 echo reply ✓
  → ping 0% 丢包
```

`ip_forward=1` 让内核能把回复从 vethint0 路由到 vethext0，ping 通了。

**场景 3：镜像模式 + `ip_forward=0`**

```
请求路径（去程）, ping 10.0.1.1:
ext → vethext0 RX → XDP BPF_F_BROADCAST
  → 克隆副本到 vethint0 → vethint1 (镜像副本 1) ✓
  → 原包继续走内核栈 (BROADCAST 在 SKB 模式不消费原包)
    → 目标 10.0.1.1 是本机 IP → 本地交付 → 回复 echo reply ✓

回复路径:
vethext0 内核 → echo reply → vethext0 TX → vethext1 → ext 收到 ✓
  (本地回复，不跨网卡，不需要 ip_forward)

但是 ping 10.0.2.2 时:
  → 克隆副本到 vethint0 → vethint1 → 回复 echo reply
  → 回复走 vethint1 → vethint0 → 需要路由到 vethext0
  → ip_forward=0 → 拒绝转发 ✗ → ping 10.0.2.2 100% 丢包
```

`ping 10.0.1.1` 通是因为目标是本机 IP（本地交付，不需 ip_forward）；`ping 10.0.2.2` 不通是因为回复需要跨网卡路由。

**场景 4：镜像模式 + `ip_forward=1`**

```
请求路径（去程）, ping 10.0.2.2:
ext → vethext0 RX → XDP BPF_F_BROADCAST
  → 克隆副本到 vethint0 → vethint1 (镜像副本 1) ✓
  → 原包继续走内核栈
    → 目标 10.0.2.2 不是本机 IP → ip_forward=1 → 转发到 vethint0
    → vethint1 收到 (内核转发副本 2) ← 这就是 vethint1 上的第二份副本!

回复路径:
vethint1 → vethint0 → ip_forward=1 → vethext0 → vethext1 → ext ✓
  → ping 0% 丢包
```

这就是为什么 `ip_forward=1` 时 vethint1 上看到两份副本：副本 1 来自 XDP BROADCAST 克隆，副本 2 来自原包走内核栈后 ip_forward 转发。

### 总结表

| 场景 | ip_forward | ping 10.0.1.1 | ping 10.0.2.2 | vethint1 副本数 |
|---|---|---|---|---|
| 转发模式 | 0 | ✅ (XDP_PASS, 本地交付) | ❌ (回复跨网卡被拒) | 0 (不匹配网段, XDP_PASS) |
| 转发模式 | 1 | ✅ | ✅ (回复经内核路由) | 1 (XDP redirect) |
| 镜像模式 | 0 | ✅ (原包到内核, 本地交付) | ❌ (回复跨网卡被拒) | 1 (仅 XDP 克隆) |
| 镜像模式 | 1 | ✅ | ✅ (回复经内核路由) | 2 (XDP 克隆 + 内核转发) |

### 核心要点

1\. **XDP redirect（普通）消费原包** → 内核看不到 → 只有 XDP 路径
2\. **XDP BROADCAST 在 SKB 模式不消费原包** → 内核也处理 → 两条路径都有
3\. **ip_forward 控制内核跨网卡路由** → 回复从 vethint0 到 vethext0 必须开启
4\. **本地交付不需要 ip_forward** → 目标是本机 IP 时内核直接处理

