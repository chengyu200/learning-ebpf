# 24-hide — 隐藏目录条目

通过 sys_enter/exit_getdents64 tracepoint 配对，遍历返回的 dirent 缓冲区，将匹配目标前缀的条目的 d_ino 置零（使 ls 隐藏该条目）。

## 运行
```bash
make -C src/24-hide
sudo ./src/24-hide/hide test  # 隐藏以 'test' 开头的文件
```
