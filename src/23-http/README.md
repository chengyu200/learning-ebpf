# 23-http

通过 socket filter 在链路层捕获并解析 TCP/IPv4 包（含 HTTP 请求行）。

## 做什么
- 内核态：`SEC("socket")` 程序绑定到 raw packet socket，解析以太网/IP/TCP 头，将源/目的地址、端口和 payload 前若干字节通过 ring buffer 发送到用户态。
- 用户态：创建 `AF_PACKET` raw socket 绑定到指定网卡，用 `SO_ATTACH_BPF` 挂载 socket filter 程序，轮询 ring buffer 打印。

## 教学概念
- `socket` 程序类型、`bpf_skb_load_bytes` 逐层解析包头。
- raw packet socket (`AF_PACKET`) 与 `SO_ATTACH_BPF` 挂载方式。
- `__sk_buff` 边界检查、`bpf_htons`/`bpf_ntohs` 字节序转换。

## 运行
```bash
make -C src/23-http
sudo ./src/23-http/http  -i  lo
# 另开终端：curl -s http://127.0.0.1/  或 ping 127.0.0.1
```
