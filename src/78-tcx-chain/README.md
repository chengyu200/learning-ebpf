# 78-tcx-chain: TCX 链式调用演示

## 目标

演示 TCX chaining：多个 BPF 程序附加到同一 hook 点，通过返回值控制链是否继续。

## 关键发现

### TCX 专用返回值 vs TC 返回值

TCX 使用 `enum tcx_action_base`（`linux/bpf.h`）而非传统 TC 的 `TC_ACT_*`：

| TCX 返回值 | 数值 | 含义 | 对应 TC 值 |
|-----------|------|------|-----------|
| `TCX_NEXT` | -1 | **继续链**（下一个程序执行） | `TC_ACT_UNSPEC` |
| `TCX_PASS` | 0 | 放行，**停止链** | `TC_ACT_OK` |
| `TCX_DROP` | 2 | 丢弃，**停止链** | `TC_ACT_SHOT` |
| `TCX_REDIRECT` | 7 | 重定向，**停止链** | `TC_ACT_REDIRECT` |

**重要**：`TC_ACT_PIPE (3)` 不是 TCX 的正式返回值！内核注释说"unknown return codes are mapped to TCX_NEXT"，但实际测试中 `TC_ACT_PIPE` 未能可靠触发链式传递。**正确做法是返回 `TCX_NEXT (-1)`。**

### 链式顺序

使用空 `bpf_tcx_opts`（无 `relative_fd`）时，程序按 attach 顺序追加到链尾（FIFO）：

```
attach prog_a → chain: [prog_a]
attach prog_b → chain: [prog_a → prog_b]
```

也可用 `BPF_F_BEFORE` / `BPF_F_AFTER` + `relative_fd` 显式控制插入位置。

## 设计

两个 `SEC("tcx/ingress")` 程序组成链：

```
prog_a (第一个) → prog_b (第二个)
  返回值可配置      固定返回 TCX_PASS
```

全局变量 `chain_action` 由用户态在加载前设置：

| 模式 | `chain_action` | prog_a 返回 | 效果 |
|------|---------------|------------|------|
| 默认 | `TCX_NEXT (-1)` | 继续链 | prog_a 和 prog_b 都看到包 |
| `--pass` | `TCX_PASS (0)` | 停止链 | 只有 prog_a 看到包 |

## 运行

```bash
# 确保 veth 环境存在
sudo ./scripts/setup-veth.sh create

# 编译
make -C src/78-tcx-chain

# TCX_NEXT 模式（链继续）
sudo ./src/78-tcx-chain/tcx_chain

# TCX_PASS 模式（链停止）
sudo ./src/78-tcx-chain/tcx_chain --pass

# 生成流量（另一个终端）
sudo ip netns exec bpfns ping 192.168.99.1
```

## 输出示例

### TCX_NEXT 模式（默认）

```
TCX chain attached to vethbpf0 (2 programs: prog_a -> prog_b).
Mode: TCX_NEXT (chain continues to prog_b)

Program         Packets
--------        -------
prog_a                5
prog_b                5
```

prog_a 返回 `TCX_NEXT`，链继续，prog_b 也看到 5 个包。

### TCX_PASS 模式（--pass）

```
TCX chain attached to vethbpf0 (2 programs: prog_a -> prog_b).
Mode: TCX_PASS (chain stops at prog_a)

Program         Packets
--------        -------
prog_a                5
prog_b                0
```

prog_a 返回 `TCX_PASS`，链停止，prog_b 未执行（0 包）。

## 验证链结构

```bash
# 运行 tcx_chain 后，在另一个终端查看
sudo bpftool net list dev vethbpf0
# 输出:
# tc:
# vethbpf0(123) tcx/ingress prog_a prog_id 8427 link_id 476
# vethbpf0(123) tcx/ingress prog_b prog_id 8428 link_id 477
```

## 文件结构

- `tcx_chain.bpf.c` — 2 个 tcx/ingress 程序 + per-CPU 统计 map + 全局变量
- `tcx_chain.c` — 用户态加载器（参数解析 + open/load/attach + 统计打印）
- `tcx_chain.h` — TCX_NEXT / TCX_PASS 定义
- `Makefile` — `APP := tcx_chain`

## 与 76-tc-tcx 的关系

`76-tc-tcx` 演示 `tc/` 和 `tcx/` 是别名（同一 attach type），但所有程序返回 `TCX_PASS`，链停止。
本示例进一步演示 `TCX_NEXT` 如何让链继续，对比两种返回值的效果。
