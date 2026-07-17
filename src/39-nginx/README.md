# 39-nginx — 追踪 Nginx 请求

uprobe 挂 nginx 的 ngx_http_process_request（入口+uretprobe），测量每个请求的处理耗时。

## 运行
```bash
make -C src/39-nginx
sudo ./src/39-nginx/nginx  # 需先启动 nginx 并发请求
```
