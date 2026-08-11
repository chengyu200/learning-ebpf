# 81-sk-skb: TCP 流解析器与 Verdict

## 目标

演示 `BPF_PROG_TYPE_SK_SKB` 的 `stream_parser` 和 `stream_verdict` 挂载点，在内核层面将 TCP 字节流切分为消息，再逐条做 verdict。

## 程序类型与挂载点

**程序类型**：`BPF_PROG_TYPE_SK_SKB`
**上下文**：`struct __sk_buff`（与 TC 相同，但可访问 `family`/`local_ip`/`remote_ip`/`local_port`/`remote_port` 字段）

| SEC | 挂载类型 | 作用 | 返回值 |
|-----|---------|------|--------|
| `sk_skb/stream_parser` | `BPF_SK_SKB_STREAM_PARSER` | 解析 TCP 流，返回消息长度 | N=消息字节数, 0=等待更多数据 |
| `sk_skb/stream_verdict` | `BPF_SK_SKB_STREAM_VERDICT` | 对解析出的消息做 verdict | `SK_PASS`(1)=放行, `SK_DROP`(0)=丢弃 |
| `sk_skb/verdict` | `BPF_SK_SKB_VERDICT` | 新版 verdict-only（不需 parser） | 同上 |
| `sk_skb` (bare) | 0 (无) | legacy/generic 形式 | — |

> **`sk_skb/verdict`** 是内核 5.12 引入的新 attach 点，不需要 `stream_parser` 即可对单个 skb 做 verdict。本示例使用经典的 `stream_parser + stream_verdict` 组合。

## 消息协议

```
[4-byte BE length] [payload]
e.g. \x00\x00\x00\x05Hello  (total 9 bytes)
```

## stream_parser 工作原理

```c
SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb)
{
    if (skb->len < 4) return 0;              // 不够 header，等数据
    bpf_skb_pull_data(skb, 4);               // 确保 4 字节可访问
    __u32 payload_len = bpf_ntohl(*(__u32 *)data);  // 读 BE 长度
    __u32 total = 4 + payload_len;
    if (skb->len < total) return 0;          // 不够整条消息，等数据
    return total;                            // 返回消息长度
}
```

内核调用流程：
1. 新数据到达 SOCKMAP 中的 socket → 内核调用 `stream_parser`
2. `stream_parser` 返回 N → 内核取前 N 字节作为一条消息
3. 内核调用 `stream_verdict` 处理这条消息
4. 剩余数据再次调用 `stream_parser`（循环直到返回 0）
5. `stream_verdict` 返回 `SK_PASS` → 数据交付用户态 `recv()`

## Attach 方式

```c
/* 两个程序都 attach 到同一个 SOCKMAP */
bpf_program__attach_sockmap(skel->progs.stream_parser,  sockmap_fd);
bpf_program__attach_sockmap(skel->progs.stream_verdict, sockmap_fd);

/* 从用户态将 socket 加入 SOCKMAP 才会触发 BPF 程序 */
__u32 key = 0, val = client_fd;
bpf_map_update_elem(sockmap_fd, &key, &val, BPF_ANY);
```

## 运行

```bash
make -C src/81-sk-skb
sudo ./src/81-sk-skb/sk_skb
```

## 输出示例

```
BPF sk_skb programs attached to SOCKMAP.
TCP server listening on 127.0.0.1:40803

	[child] connected to 127.0.0.1:40803
	[child] sent msg 1: "Hello" (9 bytes)
	[parent] accepted connection
	[parent] client socket added to SOCKMAP (key=0)

[PARSED ] msg_size=9   payload=5   local_port=40803  remote_port=0      AF_INET
[RECV   ] msg 1: "Hello" (9 bytes total)
	[child] sent msg 2: "World!!" (11 bytes)
[PARSED ] msg_size=11  payload=7   local_port=40803  remote_port=0      AF_INET
[RECV   ] msg 2: "World!!" (11 bytes total)
	[child] sent msg 3: "foo" (7 bytes)
[PARSED ] msg_size=7   payload=3   local_port=40803  remote_port=0      AF_INET
[RECV   ] msg 3: "foo" (7 bytes total)
	[child] done

3 messages parsed by BPF stream_parser.
```

## 与 29-sockops 的对比

| | 29-sockops | 81-sk-skb (本示例) |
|---|---|---|
| **程序类型** | `CGROUP_SOCK_ADDR` (sockops) + `SK_MSG` | `SK_SKB` |
| **路径** | 发送路径 (`tcp_sendmsg`) | 接收路径 (socket rx) |
| **上下文** | `struct sk_msg_md` | `struct __sk_buff` |
| **重定向 helper** | `bpf_msg_redirect_hash` | `bpf_sk_redirect_map` |
| **Map 类型** | `BPF_MAP_TYPE_SOCKHASH` | `BPF_MAP_TYPE_SOCKMAP` |
| **功能** | 旁路 TCP/IP 栈，直接转发到对端 ingress | TCP 流解析为消息 |

> 两者组合构成 **sockmap 三件套**（sockops + sk_msg + sk_skb），可用于实现零拷贝应用层代理。

## 关键 API

| API | 说明 |
|-----|------|
| `bpf_program__attach_sockmap(prog, map_fd)` | 将 SK_SKB 程序 attach 到 SOCKMAP |
| `bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY)` | 将 socket fd 写入 SOCKMAP |
| `bpf_skb_pull_data(skb, len)` | 确保 skb 线性区有足够数据可访问 |
| `bpf_sk_redirect_map(skb, map, key, flags)` | 在 verdict 中重定向到另一个 socket |
| `SK_PASS` / `SK_DROP` | verdict 返回值（1=放行, 0=丢弃） |

## 文件结构

- `sk_skb.bpf.c` — stream_parser + stream_verdict + SOCKMAP + ringbuf
- `sk_skb.c` — 用户态加载器（TCP server + fork client + ringbuf 消费）
- `sk_skb.h` — 共享定义（event 结构体）
- `Makefile` — `APP := sk_skb`
