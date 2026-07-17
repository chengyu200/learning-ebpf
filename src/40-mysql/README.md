# 40-mysql — 追踪 MySQL 查询 (仅编译)

uprobe 挂 mysqld 的 dispatch_command，捕获 SQL 查询文本。**本机无 mysqld，仅保证编译通过。** 运行需安装并启动 mysqld（带调试符号）。

## 运行
```bash
make -C src/40-mysql
sudo ./src/40-mysql/mysql /path/to/mysqld
```
