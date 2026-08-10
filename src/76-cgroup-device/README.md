# 76-cgroup-device

用 `BPF_PROG_TYPE_CGROUP_DEVICE` 实现设备白名单防火墙：控制 cgroup 内进程对设备（块设备/字符设备）的访问权限。

## 什么是 BPF CGROUP_DEVICE

`BPF_PROG_TYPE_CGROUP_DEVICE` 是 **设备 cgroup 控制器的 BPF 版本**。它允许 BPF 程序控制 cgroup 内进程对设备的访问——包括 `mknod`（创建设备节点）、`read`（读设备）、`write`（写设备）。

这是 Docker/K8s 容器中 `--device` 选项和 `devices.allow/deny` 的底层机制，用 BPF 实现更灵活的设备访问控制。

### 上下文：`struct bpf_cgroup_dev_ctx`

```c
struct bpf_cgroup_dev_ctx {
    __u32 access_type;  // 编码：(BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*
    __u32 major;        // 设备主号
    __u32 minor;        // 设备次号
};
```

- **访问操作**（高 16 位）：`MKNOD`(1<<0)、`READ`(1<<1)、`WRITE`(1<<2)
- **设备类型**（低 16 位）：`BLOCK`(1<<0)、`CHAR`(1<<1)
- **返回值**：`1` = 允许访问，`0` = 拒绝访问

### 与其他 cgroup BPF 类型的对比

| 类型 | SEC | 作用 | 返回值 |
|------|-----|------|--------|
| `CGROUP_SKB` | `cgroup_skb/egress` | 过滤网络包 | 1=allow, 0=deny |
| `CGROUP_SYSCTL` | `cgroup/sysctl` | 拦截 sysctl 读写 | 1=allow, 0=deny |
| `CGROUP_DEVICE` | `cgroup/dev` | 控制设备访问 | **1=allow, 0=deny** |
| `LSM_CGROUP` | `lsm_cgroup/...` | 安全策略 | **0=allow, 1=deny** ← 相反！ |

## 做什么

- 创建专用子 cgroup
- 用 hash map 配置设备白名单：
  - `/dev/null` (1:3) → mknod\|read\|write
  - `/dev/zero` (1:5) → mknod\|read\|write
  - `/dev/urandom` (1:9) → read
- `SEC("cgroup/dev")` BPF 程序：查找白名单，允许/拒绝设备访问，发送 ringbuf 事件
- fork 子进程进入 cgroup，测试：
  1. `open /dev/zero` + read → **ALLOWED**（白名单允许 read）
  2. `open /dev/mem` + read → **DENIED**（不在白名单，EACCES）
  3. `mknod` 创建设备节点 → **DENIED**（不在白名单，EACCES）

## 运行

```bash
make -C src/76-cgroup-device
sudo ./src/76-cgroup-device/cgroup-device
```

### 输出示例

```
BPF cgroup/dev device allowlist attached to /sys/fs/cgroup/cg-dev-demo
  Allowlist:
    char 1:3  (/dev/null    ) → mknod|read|write
    char 1:5  (/dev/zero    ) → mknod|read|write
    char 1:9  (/dev/urandom ) → read

Child (in cgroup) testing device access:
  [child] moved into cgroup (pid=12345)

  [child] test 1: open /dev/zero for read...
  [child] PASS: /dev/zero read OK (got 4 bytes)

  [child] test 2: open /dev/mem for read...
  [child] PASS: /dev/mem denied (EACCES)

  [child] test 3: mknod testdev c 1 99...
  [child] PASS: mknod denied (Operation not permitted)

  [child] All tests passed.

Events from BPF (above) match the test results.
```

ringbuf 事件会在子进程测试时实时打印：
```
  [ALLOW] char  1:5  access=read        pid=12345  comm=cgroup-device
  [DENY]  char  1:1  access=read        pid=12345  comm=cgroup-device
  [DENY]  char  1:99  access=mknod      pid=12345  comm=cgroup-device
```

## 教学概念

| 概念 | 说明 |
|------|------|
| `SEC("cgroup/dev")` | cgroup 设备控制 BPF 程序 |
| `bpf_cgroup_dev_ctx` | 上下文：`access_type` + `major` + `minor` |
| `access_type` 编码 | 高 16 位 = 访问操作（MKNOD/READ/WRITE），低 16 位 = 设备类型（BLOCK/CHAR） |
| `BPF_DEVCG_ACC_MKNOD/READ/WRITE` | 三种设备访问操作 |
| `BPF_DEVCG_DEV_BLOCK/CHAR` | 块设备/字符设备 |
| `bpf_program__attach_cgroup` | 通用 cgroup attach API（与 cgroup_skb/sysctl 相同） |
| hash map 白名单 | 动态配置允许的设备列表，key=(major,minor) → value=allow_mask |
| 返回值 `1`/`0` | `1` = 允许，`0` = 拒绝（与 lsm_cgroup 的 `0`/`1` **相反**） |
| `mknod` 系统调用 | 创建设备节点，也受 cgroup/dev 控制 |

## 技术细节

### access_type 编码

`access_type` 是一个 32 位整数，编码了两部分信息：

```c
/* 提取 */
__u32 acc = ctx->access_type >> 16;       /* 访问操作：BPF_DEVCG_ACC_* */
__u32 dev = ctx->access_type & 0xFFFF;    /* 设备类型：BPF_DEVCG_DEV_* */

/* 检查 */
if (dev & BPF_DEVCG_DEV_CHAR)  { /* 字符设备 */ }
if (dev & BPF_DEVCG_DEV_BLOCK) { /* 块设备 */ }
if (acc & BPF_DEVCG_ACC_READ)  { /* 读操作 */ }
if (acc & BPF_DEVCG_ACC_WRITE) { /* 写操作 */ }
if (acc & BPF_DEVCG_ACC_MKNOD) { /* mknod 操作 */ }
```

### hash map 白名单

用户态在 attach 前将允许的设备写入 hash map：

```c
struct dev_key key = { .major = 1, .minor = 5 };  /* /dev/zero */
struct dev_val val = { .allow_mask = BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE };
bpf_map_update_elem(allow_fd, &key, &val, BPF_ANY);
```

BPF 程序查找 map，检查请求的 access 是否在 allow_mask 中：

```c
val = bpf_map_lookup_elem(&allowlist, &key);
if (val && (val->allow_mask & acc))
    return 1;  /* 允许 */
return 0;      /* 拒绝 */
```

### 与 73-lsm-cgroup 的返回值对比

| 程序类型 | SEC | allow | deny |
|---------|-----|-------|------|
| `lsm_cgroup` | `lsm_cgroup/socket_connect` | **0** | **1** |
| `cgroup/dev` | `cgroup/dev` | **1** | **0** |

两者返回值语义**相反**，容易混淆。

## 文件结构

```
76-cgroup-device/
├── Makefile              # APP := cgroup-device
├── cgroup-device.h        # 共享：event 结构、BPF_DEVCG_* 常量
├── cgroup-device.bpf.c    # BPF 程序（hash map 白名单 + ringbuf 日志）
├── cgroup-device.c        # 加载器 + cgroup 管理 + 子进程测试 + ringbuf 消费
└── README.md
```
