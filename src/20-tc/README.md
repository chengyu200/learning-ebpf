# 20-tc

在 tc（Traffic Control）的 clsact ingress 钩子上用 eBPF 处理链路层包。

## 做什么

- 内核态：`SEC("tc")` 程序，解析 `__sk_buff` 的以太网/IP 头，对 IPv4 包用 `bpf_printk` 输出 total_len 与 ttl，返回 `TC_ACT_OK` 放行。
- 用户态：用 libbpf 的 `bpf_tc_hook_create`（建 clsact）+ `bpf_tc_attach`（挂到 ingress）把程序挂到指定网卡；退出时清理 qdisc。

## 教学概念

- tc clsact qdisc、ingress/egress attach_point、`bpf_tc_*` API。
- `__sk_buff` 的 `data`/`data_end` 边界检查、L2/L3 头解析、`bpf_htons`/`bpf_ntohs`。
- 与 XDP（21）对比：tc 在链路层、晚于 XDP，已分配 `sk_buff`。

## 运行

```bash
make -C src/20-tc
# 建议先建 veth 对（默认 vethbpf0）：
sudo ./scripts/setup-veth.sh create
sudo ./src/20-tc/tc vethbpf0
# 另开终端产生流量：
sudo ip netns exec bpfns ping 192.168.99.1
# 或查看原始 trace：sudo cat /sys/kernel/tracing/trace_pipe
```

## 适配说明

原教程用 eunomia 的 `/// @tchook` 注解加载；本仓库改为标准 libbpf `bpf_tc_*` API（需用 `LIBBPF_OPTS` 设置结构体的 `.sz` 字段）。
