# 5-uprobe-bashreadline

用 **uretprobe** 捕获 bash 命令行输入。

## 做什么

- 内核态：在 `/bin/bash:readline` 返回处挂 uretprobe，读取返回值（即用户键入的那一行），连同 pid/comm 发送到 ring buffer。
- 用户态：轮询 ring buffer 打印。

## 教学概念

- uprobe / uretprobe 挂载用户态函数。
- `BPF_KRETPROBE` 宏捕获函数返回值（`PT_REGS_RC`）。
- `bpf_probe_read_user_str` 读取用户态内存。

## 运行

```bash
make -C src/5-uprobe-bashreadline
sudo ./src/5-uprobe-bashreadline/bashreadline
# 另开一个交互式 bash 终端，键入命令即可看到
```

## 适配说明

本示例默认挂钩 `/bin/bash:readline`（已验证 `/bin/bash` 导出该符号）。若你的 bash 未导出 `readline`（静态编译或 readline 在共享库），可改挂 libreadline：

```bash
# 定位 readline 所在
readelf -sW /lib/aarch64-linux-gnu/libreadline.so.8 | grep ' readline'
# 把 *.bpf.c 中 SEC("uretprobe//bin/bash:readline") 改为
# SEC("uretprobe//lib/.../libreadline.so.8:readline") 后重新编译
```
