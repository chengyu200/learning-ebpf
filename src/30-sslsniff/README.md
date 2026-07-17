# 30-sslsniff — uprobe 捕获 SSL/TLS 明文

uprobe 挂 libssl 的 SSL_write（入口取 buf）和 SSL_read（uretprobe 取返回数据），将明文通过 ring buffer 输出。

## 运行
```bash
make -C src/30-sslsniff
sudo ./src/30-sslsniff/sslsniff  # 另开终端: curl https://1.1.1.1
```
