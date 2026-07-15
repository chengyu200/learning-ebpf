# 19-lsm-connect

用 BPF LSM 在 `socket_connect` 钩子上拦截到指定 IP（1.1.1.1）的连接。

## 做什么

- 内核态：`SEC("lsm/socket_connect")` 程序，检查 `sa_family==AF_INET` 且目标地址 == 1.1.1.1，则返回 `-EPERM` 拒绝；遵循“不可覆盖既有拒绝”的 LSM 规则。
- 用户态：加载/attach；attach 失败时给出启用提示。attach 成功后读取 trace_pipe。

## 教学概念

- BPF LSM 程序类型、`SEC("lsm/...")`、`BPF_PROG` 的 `ret` 参数（前序检查结果）。
- 函数级安全策略的精准控制。

## 运行（需要 bpf 处于活跃 LSM 列表）

本机 `CONFIG_BPF_LSM=y`，但 `bpf` **不在**活跃 LSM 列表（`/sys/kernel/security/lsm`），故此示例**仅保证编译通过**；加载器 attach 会失败并给出提示。运行需要：

1. 确认：`cat /sys/kernel/security/lsm` —— 若无 `bpf`：
2. 修改内核命令行追加 `lsm=...,bpf`（如在 `/etc/default/grub` 的 `GRUB_CMDLINE_LINUX`）并重启。
3. 启用后：
   ```bash
   sudo ./src/19-lsm-connect/lsm-connect
   # 另开终端：curl 1.1.1.1  → 预期 "Operation not permitted"
   ```
