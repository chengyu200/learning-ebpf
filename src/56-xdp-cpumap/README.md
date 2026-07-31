# 56-xdp-cpumap — XDP CPUMAP 跨 CPU 重定向

## 概述

用 XDP CPUMAP（`BPF_MAP_TYPE_CPUMAP`）将数据包从接收 CPU 重定向到另一个 CPU 处理。ingress 程序在 CPU A 接收包，通过 `bpf_redirect_map` 重定向到 CPU B，cpumap 程序在 CPU B 上运行后放行到协议栈。

### CPUMAP 原理

```
                    CPU 0 (接收)
                    ┌──────────────┐
  网卡 ingress ───→ │ SEC("xdp")   │ ── bpf_redirect_map(&cpumap, cpu=1) ──┐
                    │ ingress 程序 │                                        │
                    └──────────────┘                                        │
                                                                             │
                    CPU 1 (目标)                                             │
                    ┌──────────────┐ ←──────────────────────────────────────┘
                    │SEC("xdp/     │
                    │  cpumap")    │ ── XDP_PASS (在 CPU 1 上继续协议栈处理)
                    │ cpumap 程序  │
                    └──────────────┘
```

- **ingress 程序**（`SEC("xdp")`）：在接收 CPU 上运行，`bpf_redirect_map` 重定向到目标 CPU
- **cpumap 程序**（`SEC("xdp/cpumap")`）：在目标 CPU 上运行，处理后 `XDP_PASS` 放行
- **cpumap map**：key=CPU id，value=`struct bpf_cpumap_val { qsize, bpf_prog.fd }`

### CPU 选择策略

ingress 程序用 `bpf_get_smp_processor_id() ^ 1` 简单异或，将包重定向到另一个 CPU。

## 与其他 XDP 示例对比

| 示例 | XDP 动作 | 程序数 | 特点 |
|---|---|---|---|
| [21-xdp](../21-xdp) | XDP_PASS | 1 | 最小示例 |
| [41-xdp-tcpdump](../41-xdp-tcpdump) | XDP_PASS + ringbuf | 1 | 捕获 TCP 五元组 |
| [42-xdp-loadbalancer](../42-xdp-loadbalancer) | XDP_REDIRECT (bpf_redirect_peer) | 1 | L4 负载均衡 |
| [46-xdp-test](../46-xdp-test) | XDP_PASS | 1 | per-CPU 包计数 |
| [55-xdp-devmap](../55-xdp-devmap) | — | — | DEVMAP 重定向 |
| **本示例** | **XDP_REDIRECT (bpf_redirect_map + CPUMAP)** | **2** | **跨 CPU 重定向** |

## 编译与运行

```bash
# 编译
make -C src/56-xdp-cpumap

# 建 veth 对（如已存在可跳过）
sudo ./scripts/setup-veth.sh create

# 启动（默认 vethbpf0，可指定网卡）
sudo ./src/56-xdp-cpumap/xdp-cpumap vethbpf0

# 另开终端，从 bpfns 产生流量
sudo ip netns exec bpfns ping 192.168.99.1

# Ctrl-C 停止，查看 per-CPU 分布统计
```

## 输出示例

```
cpumap: 4 CPUs configured (qsize=4096, prog_fd=8)
xdp-cpumap: redirecting on vethbpf0 (DRV mode)
Press Ctrl-C to stop.

=== Per-CPU Packet Distribution ===

  CPU    RX(ingress)       CPUMAP(processed)
  ------ ---------------- --------------------
  0      1247             0
  1      0                1247

  Total RX: 1247    Total CPUMAP: 1247    Redirect rate: 100%
```

## 文件结构

```
56-xdp-cpumap/
├── Makefile
├── README.md
├── xdp-cpumap.h          # 共享常量（MAX_CPUS, CPUMAP_QSIZE）
├── xdp-cpumap.bpf.c      # 2 个 XDP 程序 + 3 个 map
└── xdp-cpumap.c          # 用户态：创建 cpumap + attach + 周期统计
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `BPF_MAP_TYPE_CPUMAP` | CPUMAP 类型，value 为 `bpf_cpumap_val` |
| `SEC("xdp/cpumap")` | cpumap 程序，在目标 CPU 上运行 |
| `bpf_redirect_map` | XDP 重定向到 map 指定的目标（CPU/网卡） |
| `struct bpf_cpumap_val` | CPUMAP value：qsize + 可选 cpumap prog fd |
| `XDP_FLAGS_DRV_MODE` | native XDP 模式，CPUMAP redirect 需要 |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | per-CPU 计数，统计包分布 |
| cpumap 程序 attach 方式 | 无 libbpf 辅助函数，通过 `bpf_map_update_elem` 写 fd 到 map value |

## 注意事项

- CPUMAP 重定向需要 **native XDP（DRV mode）**，SKB mode 下 `bpf_redirect_map` 到 cpumap 可能不生效
- 本程序先试 DRV mode，失败回退 SKB mode 并提示 WARNING
- 需要至少 2 个 CPU 才能看到重定向效果
