# 41-xdp-tcpdump — XDP 捕获 TCP 五元组

在 XDP hook 解析以太网/IP/TCP 头，将源/目的地址、端口、包长通过 ring buffer 输出。

## 运行
```bash
make -C src/41-xdp-tcpdump
sudo ./src/41-xdp-tcpdump/xdp-tcpdump lo  # 另开终端: curl http://127.0.0.1/
```
