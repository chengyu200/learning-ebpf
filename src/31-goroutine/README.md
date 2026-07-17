# 31-goroutine — 追踪 Go goroutine 创建

uprobe 挂 Go 运行时 runtime.newproc 符号，统计 goroutine 创建次数。

## 运行
```bash
make -C src/31-goroutine
make -C src/31-goroutine && sudo ./src/31-goroutine/goroutine src/31-goroutine/gotest
```
