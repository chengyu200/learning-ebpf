# 42-xdp-loadbalancer — XDP L4 负载均衡

按五元组哈希选择后端，重写目的 IP 和 MAC，通过 bpf_redirect_peer 转发到对端 veth。后端列表从命令行参数填充。

## 运行
```bash
make -C src/42-xdp-loadbalancer
sudo ./src/42-xdp-loadbalancer/xdp-loadbalancer vethbpf0 192.168.99.2
```
