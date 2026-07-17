# 37-uprobe-rust — uprobe 追踪 Rust 程序

用 rustc 构建一个带 slow_function 符号的小程序，uprobe 挂载该符号并捕获调用参数。

## 运行
```bash
make -C src/37-uprobe-rust
make -C src/37-uprobe-rust && sudo ./src/37-uprobe-rust/uprobe-rust src/37-uprobe-rust/target
```
