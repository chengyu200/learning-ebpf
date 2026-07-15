# 21-xdp

在 XDP（eXpress Data Path）钩子上处理网卡收包，早于内核协议栈。

## 做什么

- 内核态：`SEC("xdp")` 程序，计算包大小并用 `bpf_printk` 输出，返回 `XDP_PASS` 放行。
- 用户态：用 `bpf_xdp_attach`（`XDP_FLAGS_SKB_MODE` 通用模式，兼容 lo/veth 等无原生驱动 XDP 的网卡）挂载到指定网卡；退出时 detach。

## 教学概念

- `xdp_md` 上下文、`data`/`data_end`、XDP 动作（`XDP_PASS` 等）。
- `bpf_xdp_attach`/`detach` 与 `XDP_FLAGS_SKB_MODE`（generic）vs 原生模式。
- 与 tc（20）对比：XDP 在驱动层、早于 `sk_buff` 分配，性能更高。

## 运行

```bash
make -C src/21-xdp
sudo ./scripts/setup-veth.sh create
sudo ./src/21-xdp/xdp vethbpf0
# 另开终端产生流量：
sudo ip netns exec bpfns ping 192.168.99.1
# 或查看原始 trace：sudo cat /sys/kernel/tracing/trace_pipe
```

## 适配说明

原教程用 eunomia 的 `/// @ifindex` 注解；本仓库改为标准 libbpf `bpf_xdp_attach`，接口可命令行传参，默认 vethbpf0/lo。
