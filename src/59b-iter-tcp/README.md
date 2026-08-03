# 59b-iter-tcp — TCP 连接扫描器

## 概述

用 `SEC("iter/tcp")` 遍历系统所有 TCP 连接，输出四元组 + 状态。类似 `ss -t`，但用 BPF iterator 实现，输出格式完全可定制。

### 关于 iter/tcp 

| SEC 名 | 是否可用 | 说明 |
|---|---|---|
| `iter/tcp` | ✅ 正确 | 统一遍历 TCP 连接 |

内核中 TCP iterator 注册的 target 名是 `"tcp"`（在 `net/ipv4/tcp_ipv4.c` 中通过 `bpf_iter_reg_target()` 注册），而非 `"tcp4"`。`vmlinux.h` 中的上下文结构体名 `bpf_iter__tcp` 也印证了这一点。

## 编译与运行

```bash
make -C src/59b-iter-tcp

# 产生一些 TCP 连接
python3 -m http.server 8080 &
curl http://127.0.0.1:8080/ > /dev/null

# 扫描 TCP 连接
sudo ./src/59b-iter-tcp/iter-tcp
```

## 输出示例

```
Local Address         Port     Peer Address         Port     State
-------------------- -------- -------------------- -------- ----------
127.0.0.1             8080     127.0.0.1            37414    ESTABLISHED
127.0.0.1             37414    127.0.0.1            8080     ESTABLISHED
0.0.0.0               22       0.0.0.0              0        LISTEN
```

## 教学概念

- `SEC("iter/tcp")` + `bpf_iter__tcp` 上下文（注意不是 `iter/tcp4`）
- `bpf_seq_write` 二进制输出（对比 `BPF_SEQ_PRINTF` 文本输出）
- `BPF_CORE_READ` 读取 `sock_common` 结构体字段
- 用户态解析二进制流（按 `sizeof(struct tcp_event)` 逐条解析）
- 对比 `ss -t`：BPF iterator 可自定义输出字段和格式
