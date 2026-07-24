# 52-sk-lookup-proxy

用 `BPF_PROG_TYPE_SK_LOOKUP` 实现 L7 代理：一个后端 HTTP 服务器接收**多个端口**（8000-8099）的入站 TCP 连接，无需为每个端口 `bind()` 一个 socket。

参考了 Cloudflare 的 sk_lookup 用例：代理进程接收大量端口的连接，用 BPF 在 socket 查找阶段重定向到单个后端。

## 做什么

```
Client → connect 127.0.0.1:8000
                    ↓
         内核传输层查找 socket → 触发 sk_lookup 钩子
                    ↓
         BPF 程序：端口在 8000-8099?
                    ↓ 是
         bpf_sk_assign() → SOCKMAP[0] (后端 :9000)
                    ↓
         后端 HTTP 服务器 accept() 并响应
```

- **BPF 程序**：拦截端口 8000-8099 的 TCP 连接，从 SOCKMAP 查找后端 socket，用 `bpf_sk_assign()` 重定向
- **用户态**：创建后端 listening socket（:9000），写入 SOCKMAP，用 `bpf_link_create(BPF_SK_LOOKUP)` 挂载 BPF 程序到网络命名空间，运行 HTTP accept() 循环

## 教学概念

| 概念 | 说明 |
|------|------|
| `BPF_PROG_TYPE_SK_LOOKUP` | 在传输层 socket 查找阶段介入，可决定哪个 socket 接收入站连接 |
| `bpf_sk_assign` | BPF helper #124，将 SOCKMAP 中查到的 socket 分配给当前入站连接 |
| `bpf_sk_release` | 释放 `bpf_map_lookup_elem` 返回的 socket 引用 |
| `BPF_MAP_TYPE_SOCKMAP` | 存储 socket 引用，BPF 程序可从中查找 socket |
| `bpf_link_create(BPF_SK_LOOKUP)` | 挂载到网络命名空间（不是 cgroup 或网卡） |
| `SK_PASS` / `SK_DROP` | 返回值：放行 / 丢弃 |

## 运行

```bash
make -C src/52-sk-lookup-proxy
sudo ./src/52-sk-lookup-proxy/sk-lookup-proxy
# 另开终端：
curl http://127.0.0.1:8000   # → Hello from sk_lookup proxy!
curl http://127.0.0.1:8050   # → 同样的响应
curl http://127.0.0.1:8099   # → 同样的响应
curl http://127.0.0.1:7000   # → Connection refused（不在 8000-8099 范围）
curl http://127.0.0.1:9000   # → 直接访问后端，也工作
```

## 输出示例

```
Backend HTTP server listening on 127.0.0.1:9000
Backend socket fd=3 written to SOCKMAP
BPF sk_lookup program attached to netns
Proxying ports 8000-8099 → backend :9000

[9] connection from 127.0.0.1:44914
[9] connection from 127.0.0.1:58242
```

curl 响应：
```
Hello from sk_lookup proxy!
Backend is listening on port 9000.
You connected to a port in range 8000-8099.
```

## 与其他网络示例的关系

| 示例 | 程序类型 | 网络栈位置 | 核心能力 |
|------|---------|-----------|---------|
| 21-xdp | XDP | 驱动层（最早） | 包修改/丢弃/redirect |
| 42-xdp-loadbalancer | XDP | 驱动层 | L4 负载均衡（IP/MAC 重写） |
| 20-tc / 50-tcx | TC | 链路层 | 流量分类/计数 |
| 29-sockops | sock_ops+sk_msg | socket 层 | socket 间消息重定向 |
| **52-sk-lookup-proxy** | **sk_lookup** | **传输层 socket 查找** | **选择哪个 socket 接收入站连接** |

sk_lookup 是唯一能在 socket 查找阶段做决策的 BPF 程序类型，填补了 XDP/TC 和应用层之间的空白。

## Cloudflare 场景

Cloudflare 用 sk_lookup 接收**所有端口**的入站连接并路由到代理进程：
- 无需为每个端口 `bind()` → 节省 fd 和内存
- 无需 `IPADDR_ANY` 通配 → 避免端口冲突
- 代理进程可以做 L7 路由（按 Host header、SNI 等转发到不同后端）
