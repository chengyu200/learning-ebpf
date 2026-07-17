# 29-sockops — 加速本地网络请求转发

用 sockops (BPF_SOCK_OPS) + sk_msg (BPF_MSG_REDIRECT) 程序在本地进程间直接转发 TCP 包，绕过 TCP/IP 协议栈。sockops 程序在连接建立时把 sockhash 填充；sk_msg 程序在发包时查找目标 socket 并 redirect。

## 运行
```bash
make -C src/29-sockops
sudo ./src/29-sockops/bpf_contrack  # 需先建 veth: ./scripts/setup-veth.sh create
```
