# 73-lsm-cgroup — cgroup 级 LSM 安全策略

## 概述

用 `SEC("lsm_cgroup/socket_connect")` 实现 **cgroup 级**的网络安全策略：仅对 cgroup 内进程阻止 `connect 127.0.0.1:9999`，不影响系统其他进程。

### lsm_cgroup vs lsm/mac

| 维度 | `SEC("lsm/...")` (19-lsm-connect) | `SEC("lsm_cgroup/...")` (本示例) |
|---|---|---|
| 作用范围 | **全局**（系统所有进程） | **cgroup 内**（仅 cgroup 成员） |
| 挂载方式 | `bpf_program__attach_lsm`（自动） | `bpf_program__attach_cgroup`（手动） |
| 返回值 | `0` = allow，`-EPERM` = deny | **`0` = deny，`1` = allow**（与 lsm/mac 完全相反！） |
| 隔离性 | 影响所有进程 | 仅 cgroup 成员 |
| 自动 attach | ✅ skeleton 自动 | ❌ 手动 |

### 真实使用场景

- **容器安全隔离**：容器在独立 cgroup 中，lsm_cgroup 策略只影响容器内进程
- **多租户隔离**：不同租户 cgroup 有不同安全策略
- **策略 A/B 测试**：策略只影响指定 cgroup，不影响系统其他部分

## 编译与运行

```bash
make -C src/73-lsm-cgroup
sudo ./src/73-lsm-cgroup/lsm-cg
```

程序自包含：自动创建子 cgroup → fork 子进程进入 cgroup 测试 → 父进程在 cgroup 外对比 → 清理。

## 输出示例

```
lsm_cgroup attached to /sys/fs/cgroup/lsm-cgroup-demo
  Policy: block connect to 127.0.0.1:9999 for cgroup members

  [child] moved into cgroup (pid=34867)
  [child] connect :9999 → errno=1 (Operation not permitted)
  [child] PASS: :9999 blocked by LSM (EPERM/EACCES)
  [child] connect :8080 → errno=111 (Connection refused)
  [child] PASS: :8080 not blocked by LSM
  [child] All tests passed.

Parent (outside cgroup) testing:
  PASS: connect :9999 not blocked (refused (no server))

All tests done. Cleaning up.
```

## 文件结构

```
73-lsm-cgroup/
├── Makefile
├── README.md
├── lsm-cg.h              # 共享：常量（阻止 IP/端口/cgroup 路径）
├── lsm-cg.bpf.c          # SEC("lsm_cgroup/socket_connect") 安全策略
└── lsm-cg.c              # 用户态：cgroup 管理 + attach + 测试
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `SEC("lsm_cgroup/...")` | cgroup 级 LSM 程序 |
| `BPF_LSM_CGROUP` | attach type，通过 cgroup fd 挂载 |
| 返回值 `0`/`1` | **`0` = deny，`1` = allow**（与 lsm/mac 的 `0=allow/-EPERM=deny` 完全相反！） |
| `bpf_program__attach_cgroup` | 手动 attach 到 cgroup fd |
| `bpf_probe_read_kernel` | 安全读取内核内存（验证器拒绝直接解引用） |
| cgroup 作用域 | 策略只影响 cgroup 成员进程 |
| 子进程 cgroup 迁移 | 写 PID 到 `cgroup.procs` 进入 cgroup |

## 与 19-lsm-connect 的对比

| 测试 | 19-lsm-connect (全局) | 73-lsm-cgroup (cgroup 级) |
|---|---|---|
| cgroup 内 connect :9999 | ❌ 被阻止 | ❌ 被阻止 |
| cgroup 外 connect :9999 | ❌ 被阻止 | ✅ 不受影响 |
| cgroup 内 connect :8080 | ✅ 正常 | ✅ 正常 |
