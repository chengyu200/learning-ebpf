# 83-flow-dissector: 自定义 BPF 流解析器

## 什么是 Flow Dissector？

Flow dissector 是内核的**包解析器**——内核在需要识别数据包属于哪个"流"时（计算 flow hash）调用它。提取的信息（源/目的 IP、端口、协议）用于：

- **RPS/RFS**：多核网卡的接收中断负载均衡，按流分配 CPU
- **conntrack**：连接跟踪，按流匹配规则
- **socket 匹配**：`bpf_sk_lookup`、`SO_COOKIE` 等

内核有内置的默认 flow dissector（解析 Ethernet/VLAN/IPv4/IPv6/TCP/UDP 等标准协议）。自定义 BPF flow dissector 可以：
- 支持非标准/自定义协议
- 解析隧道封装（VXLAN/GRE/GTP）
- 覆盖默认解析行为

## 程序类型与挂载点

**程序类型**：`BPF_PROG_TYPE_FLOW_DISSECTOR`
**挂载类型**：`BPF_FLOW_DISSECTOR`
**SEC 名称**：`SEC("flow_dissector")`（唯一，无变体）
**上下文**：`struct __sk_buff`（含 `flow_keys` 指针）
**挂载目标**：网络命名空间（`bpf_program__attach_netns`）

### 返回值

| 返回值 | 含义 |
|--------|------|
| `BPF_OK (0)` | 使用自定义解析结果 |
| `BPF_FLOW_DISSECTOR_CONTINUE (129)` | 回退到内核默认解析器 |

### struct bpf_flow_keys（输出结构体）

程序通过 `skb->flow_keys` 访问并填充此结构体：

```c
struct bpf_flow_keys {
    __u16 nhoff;         // 网络头偏移（从 data 起算）
    __u16 thoff;         // 传输头偏移（从 data 起算）
    __u16 addr_proto;    // ETH_P_* of valid addrs
    __u8  is_frag;       // 是否分片
    __u8  is_first_frag; // 是否第一个分片
    __u8  is_encap;      // 是否封装
    __u8  ip_proto;      // L4 协议（TCP=6, UDP=17, ICMP=1）
    __be16 n_proto;      // L3 协议（ETH_P_IP=0x0800）
    __be16 sport;        // 源端口（网络字节序）
    __be16 dport;        // 目的端口（网络字节序）
    __be32 ipv4_src;     // 源 IPv4（网络字节序）
    __be32 ipv4_dst;     // 目的 IPv4（网络字节序）
    __u32  flags;        // BPF_FLOW_DISSECTOR_F_* 控制标志
    __be32 flow_label;   // IPv6 flow label
};
```

## BPF 程序逻辑

程序处理两种数据包起始格式：
1. **L2 起始**（Ethernet 接口如 veth）：`data` 指向 Ethernet 头
2. **L3 起始**（loopback 接口）：`data` 直接指向 IP 头

```
Test 0: Ethernet + IPv4 + TCP
  data → [Ethernet(14)] [IPv4(20)] [TCP(20)]
  nhoff=14, thoff=34  ← 从 data 到 IP 头/TCP 头的偏移

Test 2: IPv4 only (no Ethernet, like loopback)
  data → [IPv4(20)]
  nhoff=0, thoff=20
```

解析流程：
1. 检查 `data` 是否以 IPv4 头开始（version=4, ihl>=5）→ L3 模式
2. 否则检查 Ethernet 头的 `h_proto` 是否为 `ETH_P_IP` → L2 模式
3. 解析 IP 头获取协议和地址
4. 解析 TCP/UDP 头获取端口
5. 填充 `bpf_flow_keys`
6. 返回 `BPF_OK`

## 运行

```bash
make -C src/83-flow-dissector
sudo ./src/83-flow-dissector/flow_dissector
```

## 输出示例

```
BPF flow dissector attached to netns (link active).
Testing flow dissector program logic via bpf_prog_test_run_opts.

Test 0: Ethernet + IPv4 + TCP (127.0.0.1:12345 -> 127.0.0.2:8080)
  [RINGBUF] 127.0.0.1:12345 -> 127.0.0.2:8080  TCP  nhoff=14 thoff=34
Test 1: Ethernet + IPv4 + UDP (192.168.1.1:5353 -> 192.168.1.2:53)
  [RINGBUF] 192.168.1.1:5353 -> 192.168.1.2:53  UDP  nhoff=14 thoff=34
Test 2: IPv4 only, no Ethernet (127.0.0.1 -> 127.0.0.1, ICMP)
  [RINGBUF] 127.0.0.1:0 -> 127.0.0.1:0  ICMP  nhoff=0 thoff=20

Flow dissector called 3 times (flow_keys non-NULL: 3).
```

## 测试方法：bpf_prog_test_run_opts

由于本内核未启用 `CONFIG_BPF_FLOW_DISSECTOR`，内核运行时不会主动调用 BPF flow dissector。因此使用 `bpf_prog_test_run_opts` 模拟内核调用：

1. 构造测试数据包（Ethernet + IPv4 + TCP/UDP/ICMP）
2. 调用 `bpf_prog_test_run_opts(prog_fd, &opts)` 传入 `data_in`
3. 内核设置 `skb->flow_keys` 指针并调用 BPF 程序
4. 程序解析数据包并填充 `flow_keys`
5. 通过 ringbuf 将解析结果发送到用户态

> `bpf_prog_test_run_opts` 返回 `ENOSPC` 是因为内核的通用 test_run 处理器不认识 flow_dissector 上下文类型，但程序确实被调用了（计数器=3，flow_keys 非 NULL=3），ringbuf 事件也正确产生。

## 内核配置检查

```bash
# 检查内核是否支持运行时 flow dissector 调用
grep BPF_FLOW_DISSECTOR /boot/config-$(uname -r)
```

如果没有输出，说明 `CONFIG_BPF_FLOW_DISSECTOR` 未启用：
- BPF 程序仍可加载和挂载（`bpftool net list` 可见）
- 内核运行时不会主动调用程序（RPS/RFS 不触发）
- `bpf_prog_test_run_opts` 仍可测试程序逻辑

## 关键 API

| API | 说明 |
|-----|------|
| `SEC("flow_dissector")` | BPF 程序 section 名（唯一） |
| `bpf_program__attach_netns(prog, netns_fd)` | 挂载到网络命名空间 |
| `skb->flow_keys` | `struct bpf_flow_keys *`，程序填充此结构体 |
| `bpf_prog_test_run_opts(prog_fd, &opts)` | 测试程序逻辑（不依赖内核调用） |
| `BPF_OK (0)` | 使用自定义解析结果 |
| `BPF_FLOW_DISSECTOR_CONTINUE (129)` | 回退到内核默认解析器 |

## 文件结构

- `flow_dissector.bpf.c` — 1 个 BPF 程序 + ringbuf + per-CPU 计数器
- `flow_dissector.c` — 用户态加载器（netns attach + test_run 测试 + ringbuf 消费）
- `flow_dissector.h` — 共享定义（event 结构体）
- `Makefile` — `APP := flow_dissector`
