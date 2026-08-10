# 76-tc-tcx: TC vs TCX 流量统计

## 目标

对比 `tc/` 和 `tcx/` 两种 SEC 写法，验证它们是否等价，并观察 TCX chaining 行为。

## 关键发现

### 1. tc/ingress 和 tcx/ingress 是完全等价的别名

在 libbpf 源码中，`tc/ingress` 和 `tcx/ingress` 都映射到同一个 attach type `BPF_TCX_INGRESS`：

```c
// libbpf/src/libbpf.c
SEC_DEF("tcx/ingress",    SCHED_CLS, BPF_TCX_INGRESS, SEC_NONE)
SEC_DEF("tc/ingress",     SCHED_CLS, BPF_TCX_INGRESS, SEC_NONE) /* alias for tcx */
```

两者使用相同的 attach API：`bpf_program__attach_tcx()`。

### 2. TCX Chaining 行为

当多个程序附加到同一 hook 点时，它们形成链。返回值使用 `enum tcx_action_base`：

| 返回值 | 数值 | 含义 |
|--------|------|------|
| `TCX_PASS` | 0 | 放行，**停止链**（后续程序不执行） |
| `TCX_NEXT` | -1 | 放行，**继续链**（传递给下一个程序） |
| `TCX_DROP` | 2 | 丢弃，停止链 |

> **注意**：TCX 使用自己的返回值枚举，不是传统 TC 的 `TC_ACT_*`。
> `TCX_PASS (0)` 与 `TC_ACT_OK (0)` 数值相同，但 `TCX_NEXT (-1)` 与 `TC_ACT_PIPE (3)` 不同。
> 继续链必须用 `TCX_NEXT`，详见 `src/78-tcx-chain`。

本示例中，4 个程序附加到 2 个 hook 点（ingress + egress），每个 hook 点 2 个程序。
所有程序返回 `TCX_PASS`，链停止，第二个程序看不到包。

### 3. 验证：tcx/ 程序单独附加时正常工作

当只附加 tcx/ingress + tcx/egress（不附加 tc/ 变体）时，它们正常统计流量。

## 四个程序

| SEC | 程序名 | hook 点 | 说明 |
|-----|--------|---------|------|
| `SEC("tc/ingress")` | `tc_ingress` | ingress | 统计入口 IPv4 包 |
| `SEC("tc/egress")` | `tc_egress` | egress | 统计出口 IPv4 包 |
| `SEC("tcx/ingress")` | `tcx_ingress` | ingress | 同上（别名） |
| `SEC("tcx/egress")` | `tcx_egress` | egress | 同上（别名） |

## 运行

```bash
# 确保 veth 环境存在
sudo ./scripts/setup-veth.sh create

# 编译并运行
make -C src/76-tc-tcx
sudo ./src/76-tc-tcx/tc_tcx

# 另一个终端，生成流量
sudo ip netns exec bpfns ping 192.168.99.1
```

## 输出示例

```
TC/TCX programs attached to vethbpf0.
Note: tc/ingress and tcx/ingress attach to the same hook (aliases).
       TCX chaining: first program returns TCX_PASS, stops chain.
      So only tc/ingress and tc/egress see packets.

Program             Packets        Bytes
--------            -------        -----
tc/ingress                5          490
tc/egress                 5          490
tcx/ingress               0            0
tcx/egress                0            0
```

tc/ingress 和 tc/egress 各看到 5 个包（ping 的 5 个 ICMP echo request/reply）。
tcx/ingress 和 tcx/egress 为 0，因为同一 hook 上的第一个程序返回 `TCX_PASS` 停止了链。

## 对比三种 TC SEC 写法

| SEC 写法 | attach 方式 | API | 示例 |
|----------|------------|-----|------|
| `SEC("tc")` | legacy TC | `bpf_tc_hook_create` + `bpf_tc_attach` | `src/20-tc` |
| `SEC("tc/ingress")` | TCX (别名) | `bpf_program__attach_tcx` | 本示例 |
| `SEC("tcx/ingress")` | TCX | `bpf_program__attach_tcx` | `src/50-tcx`, 本示例 |

## 文件结构

- `tc_tcx.bpf.c` — 4 个 BPF 程序 + per-CPU 统计 map
- `tc_tcx.c` — 用户态加载器（attach + 周期打印统计）
- `tc_tcx.h` — 共享定义
