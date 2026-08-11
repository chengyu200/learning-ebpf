# 82-cgroup-skb: Cgroup 双向流量审计与端口策略

## 目标

演示 `BPF_PROG_TYPE_CGROUP_SKB` 的 ingress/egress 挂载点，实现 cgroup 级网络流量审计和基于目标端口的出站策略。

## 程序类型与挂载点

**程序类型**：`BPF_PROG_TYPE_CGROUP_SKB`
**上下文**：`struct __sk_buff`（与 TC 相同，但 `family`/`local_port`/`remote_port` 等 sk_skb 专属字段不可访问）

| SEC | 挂载类型 | 作用 | 返回值 |
|-----|---------|------|--------|
| `cgroup_skb/ingress` | `BPF_CGROUP_INET_INGRESS` | 入口包过滤/审计 | 1=放行, 0=丢弃 |
| `cgroup_skb/egress` | `BPF_CGROUP_INET_EGRESS` | 出口包过滤/审计 | 1=放行, 0=丢弃 |
| `cgroup/skb` (bare) | 0 (SEC_NONE) | legacy/generic 形式 | — |

> **返回值约定**：`1=allow, 0=drop`（filter 风格，非零即放行）。与 TC 的 `TCX_PASS(0)/TCX_DROP(2)` 不同！

## 数据包解析

cgroup_skb 可通过 `data`/`data_end` 直接访问数据包。对于 cgroup_skb，数据从 **L3（IP 头）** 开始（无 Ethernet 头）。

```c
struct iphdr *iph = (void *)(long)skb->data;
if ((void *)(iph + 1) > (void *)(long)skb->data_end)
    return 1;  // 无法解析则放行

if (iph->version != 4)
    return 1;  // 只处理 IPv4

__u8 l4_proto = iph->protocol;  // TCP(6), UDP(17), ICMP(1)
__u32 ihl = iph->ihl * 4;       // IP 头长度

// TCP/UDP 头紧跟 IP 头
void *l4 = (void *)iph + ihl;
__u16 sport = bpf_ntohs(*(__u16 *)l4);
__u16 dport = bpf_ntohs(*(__u16 *)(l4 + 2));
```

## BPF 程序

### 1. `cgroup_skb/ingress` — 入口流量审计

- 解析 IP 头获取 L4 协议
- 解析 TCP/UDP 头获取源端口
- 记录事件到 ringbuf（方向、协议、端口、大小）
- 返回 1（放行所有入口流量）

### 2. `cgroup_skb/egress` — 出口流量审计 + 端口策略

- 解析 IP 头获取 L4 协议和目标端口
- 查 config map 获取阻断端口
- 若 TCP 且目标端口 == 阻断端口 → 返回 0（丢弃）
- 否则记录事件到 ringbuf，返回 1

### 3. `cgroup/skb` (bare) — legacy 形式

`SEC_NONE` flag，`expected_attach_type=0`。旧内核中唯一的写法，内核会将其用于 ingress 和 egress 两个方向。现代代码应使用显式的 `cgroup_skb/ingress` 或 `cgroup_skb/egress`。

## 运行

```bash
make -C src/82-cgroup-skb
sudo ./src/82-cgroup-skb/cgroup_skb
```

## 输出示例

```
# ./cgroup_skb 
BPF cgroup_skb programs attached to /sys/fs/cgroup/cg-skb-demo
  ingress: count_ingress  (BPF_CGROUP_INET_INGRESS)
  egress:  filter_egress   (BPF_CGROUP_INET_EGRESS)
  Blocked egress port: 9999

Child (in cgroup) testing:

 [child] moved into cgroup (pid=133846)

 [child] TCP server on 127.0.0.1:8080
 [child] connect 127.0.0.1:8080... 
[EGRESS] proto=TCP  port=8080   size=60    ALLOWED  pid=133846 comm=cgroup_skb    // SYN client(51712)->server(8080)
[INGRESS] proto=TCP  port=51712  size=60    ALLOWED  pid=133846 comm=cgroup_skb	// 同一个SYN，服务端收到，sport=51712
[EGRESS] proto=TCP  port=51712  size=60    ALLOWED  pid=133846 comm=cgroup_skb		// SYN ACK server(8080)->client(51712)
[INGRESS] proto=TCP  port=8080   size=60    ALLOWED  pid=133846 comm=cgroup_skb	// 同一个SYN ACK，客户端收到，sport=8080
 OK (allowed)
[EGRESS] proto=TCP  port=8080   size=52    ALLOWED  pid=133846 comm=cgroup_skb		// ACK client->server（完成三次握手）
[INGRESS] proto=TCP  port=51712  size=52    ALLOWED  pid=133846 comm=cgroup_skb	// 同一个ACK，服务器端收到
[EGRESS] proto=TCP  port=8080   size=69    ALLOWED  pid=133846 comm=cgroup_skb		// PSH+ACK client->server("hello from cgroup")
[INGRESS] proto=TCP  port=51712  size=69    ALLOWED  pid=133846 comm=cgroup_skb	// 同一个数据包，服务器端收到
[EGRESS] proto=TCP  port=51712  size=52    ALLOWED  pid=133846 comm=cgroup_skb		// ACK server->client(确认收到数据)
[INGRESS] proto=TCP  port=8080   size=52    ALLOWED  pid=133846 comm=cgroup_skb	// 同一个ACK，客户端收到
[EGRESS] proto=TCP  port=51712  size=52    ALLOWED  pid=133846 comm=cgroup_skb		// FIN-ACK server->client(close（accepted）)
[INGRESS] proto=TCP  port=8080   size=52    ALLOWED  pid=133846 comm=cgroup_skb	// 同一个FIN，客户端收到
 [child] connect 127.0.0.1:9999 (blocked)... 
[EGRESS] proto=TCP  port=9999   size=60    DENIED  pid=133846 comm=cgroup_skb		// SYN client->127.0.0.1:9999 (被BPF丢弃)
[EGRESS] proto=TCP  port=9999   size=60    DENIED  pid=0 comm=swapper/1			// SYN 重传（内核softirq，pid=0 swapper/1）
 BLOCKED (Operation now in progress)

 [child] done

Done. Egress to port 9999 was blocked by BPF.
```

事件解读：
- **8080 连接**：SYN(egress) → SYN-ACK(ingress) → ACK(egress) → 数据(egress+ingress) → FIN(egress+ingress)
- **9999 连接**：SYN(egress, DENIED) → 内核重传 SYN(egress, DENIED, pid=0 swapper) → connect 超时

> `pid=0 comm=swapper/N` 的事件来自内核 softirq 上下文的 TCP SYN 重传。

## 与其他 cgroup 程序的对比

| 示例 | 程序类型 | 上下文 | 过滤对象 | 返回值 |
|------|---------|--------|---------|--------|
| `src/cgroup` | `CGROUP_SKB` | `__sk_buff` | egress 包计数 | 1=allow |
| **本示例** | `CGROUP_SKB` | `__sk_buff` | ingress + egress 包过滤 | 1=allow, 0=drop+deny |
| `79-cgroup-sock` | `CGROUP_SOCK` | `bpf_sock` | socket 创建/绑定/释放 | 1=allow, 0=deny |
| `76-cgroup-device` | `CGROUP_DEVICE` | `bpf_cgroup_dev_ctx` | 设备访问 | 1=allow, 0=deny |

> `CGROUP_SKB` 过滤**数据包**（L3/L4 级，可解析 IP/TCP 头）；
> `CGROUP_SOCK` 过滤 **socket 生命周期事件**（创建/绑定/释放，不涉及包内容）。

## 关键 API

| API | 说明 |
|-----|------|
| `bpf_program__attach_cgroup(prog, cg_fd)` | 将 cgroup_skb 程序 attach 到 cgroup |
| `bpf_get_socket_cookie(skb)` | 获取 socket cookie（唯一标识） |
| `bpf_map_update_elem(cfg_fd, &key, &port, BPF_ANY)` | 设置阻断端口 |
| `data`/`data_end` | 直接数据包访问（L3 IP 头开始） |

## 文件结构

- `cgroup_skb.bpf.c` — 2 个 BPF 程=程序（ingress + egress）+ ringbuf + config map
- `cgroup_skb.c` — 用户态加载器（cgroup 创建 + attach + fork 子进程 TCP 测试 + ringbuf 消费）
- `cgroup_skb.h` — 共享定义（event 结构体、DEMO_CGROUP）
- `Makefile` — `APP := cgroup_skb`
