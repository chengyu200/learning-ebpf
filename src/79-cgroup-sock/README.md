# 79-cgroup-sock: Socket 生命周期审计器

## 目标

演示 `BPF_PROG_TYPE_CGROUP_SOCK` 的 4 个挂载点，实现容器级 socket 生命周期审计与策略控制。

## 程序类型与挂载点

**程序类型**：`BPF_PROG_TYPE_CGROUP_SOCK`
**上下文**：`struct bpf_sock`（UAPI `linux/bpf.h`，不在 `vmlinux.h`/BTF 中）

| SEC | 挂载类型 | 触发时机 | 返回值 |
|-----|---------|---------|--------|
| `cgroup/sock_create` | `BPF_CGROUP_INET_SOCK_CREATE` | `socket()` 系统调用 | 1=允许, 0=拒绝 |
| `cgroup/post_bind4` | `BPF_CGROUP_INET4_POST_BIND` | IPv4 `bind()` 之后 | 1=允许 |
| `cgroup/post_bind6` | `BPF_CGROUP_INET6_POST_BIND` | IPv6 `bind()` 之后 | 1=允许 |
| `cgroup/sock_release` | `BPF_CGROUP_INET_SOCK_RELEASE` | socket 关闭 | 返回值忽略 |

> **`cgroup/sock`** 是 `cgroup/sock_create` 的 legacy 别名（相同 attach type `BPF_CGROUP_INET_SOCK_CREATE`），但 SEC flag 为 `SEC_ATTACHABLE_OPT`（expected_attach_type 可选）而非 `SEC_ATTACHABLE`。本示例使用 `cgroup/sock_create`。

## struct bpf_sock 字段

```c
struct bpf_sock {
    __u32 bound_dev_if;    // 绑定的网卡 index
    __u32 family;          // AF_INET, AF_INET6
    __u32 type;            // SOCK_STREAM, SOCK_DGRAM, SOCK_RAW
    __u32 protocol;        // IPPROTO_TCP(6), IPPROTO_UDP(17), IPPROTO_RAW(255)
    __u32 mark;            // socket mark
    __u32 priority;        // socket priority
    __u32 src_ip4;         // 源 IPv4
    __u32 src_ip6[4];      // 源 IPv6
    __u32 src_port;        // 源端口（主机字节序）
    __be16 dst_port;       // 目的端口（网络字节序）
    __u32 dst_ip4;         // 目的 IPv4
    __u32 dst_ip6[4];      // 目的 IPv6
    __u32 state;           // socket 状态
};
```

> **注意**：`src_port` 是主机字节序，`dst_port` 是网络字节序——两者不同！
>
> **验证器限制**：不能用 `__builtin_memcpy` 从 `ctx->src_ip6` 拷贝，因为会修改上下文指针（verifier 报 `dereference of modified ctx ptr disallowed`）。必须逐字段赋值：
> ```c
> e->src_ip6[0] = ctx->src_ip6[0];
> e->src_ip6[1] = ctx->src_ip6[1];
> // ...
> ```

## 策略

- **`sock_create`**：记录 socket 创建；拒绝 raw socket（`protocol == IPPROTO_RAW`）
- **`post_bind4`**：记录 IPv4 bind 地址和端口
- **`post_bind6`**：记录 IPv6 bind 地址和端口
- **`sock_release`**：记录 socket 释放

## 运行

```bash
make -C src/79-cgroup-sock
sudo ./src/79-cgroup-sock/cgroup-sock
```

## 输出示例

```
BPF cgroup-sock programs attached to /sys/fs/cgroup/cg-sock-demo
  Programs:
    1. cgroup/sock_create  (BPF_CGROUP_INET_SOCK_CREATE)
    2. cgroup/post_bind4   (BPF_CGROUP_INET4_POST_BIND)
    3. cgroup/post_bind6   (BPF_CGROUP_INET6_POST_BIND)
    4. cgroup/sock_release (BPF_CGROUP_INET_SOCK_RELEASE)

Note: SEC("cgroup/sock") is a legacy alias for cgroup/sock_create.
Policy: raw sockets (IPPROTO_RAW) are denied.

Child (in cgroup) testing socket operations:

[CREATE ] pid=109176 comm=cgroup-sock  AF_INET   SOCK_STREAM  proto=TCP      ALLOWED
[BIND4  ] pid=109176 comm=cgroup-sock  AF_INET   SOCK_STREAM  proto=TCP      127.0.0.1:55917
[CREATE ] pid=109176 comm=cgroup-sock  AF_INET6  SOCK_STREAM  proto=TCP      ALLOWED
[BIND6  ] pid=109176 comm=cgroup-sock  AF_INET6  SOCK_STREAM  proto=TCP      [::1]:60219
[CREATE ] pid=109176 comm=cgroup-sock  AF_INET   SOCK_DGRAM   proto=UDP      ALLOWED
[CREATE ] pid=109176 comm=cgroup-sock  AF_INET   SOCK_RAW     proto=RAW      DENIED
[RELEASE] pid=109176 comm=cgroup-sock  AF_INET   SOCK_STREAM  proto=TCP
[RELEASE] pid=109176 comm=cgroup-sock  AF_INET6  SOCK_STREAM  proto=TCP
[RELEASE] pid=109176 comm=cgroup-sock  AF_INET   SOCK_DGRAM   proto=UDP
```

事件流解读：
1. TCP IPv4 socket 创建 → **CREATE ALLOWED** → bind 127.0.0.1 → **BIND4**
2. TCP IPv6 socket 创建 → **CREATE ALLOWED** → bind [::1] → **BIND6**
3. UDP IPv4 socket 创建 → **CREATE ALLOWED**
4. Raw socket 创建 → **CREATE DENIED**（策略拒绝，`socket()` 返回 `EPERM`）
5. 关闭 3 个 socket → **RELEASE** × 3

## 与其他 cgroup 程序的对比

| 示例 | 程序类型 | 上下文 | 返回值 | 用途 |
|------|---------|--------|--------|------|
| `76-cgroup-device` | `CGROUP_DEVICE` | `bpf_cgroup_dev_ctx` | 1=allow, 0=deny | 设备访问控制 |
| `79-cgroup-sock` (本示例) | `CGROUP_SOCK` | `bpf_sock` | 1=allow, 0=deny | socket 生命周期审计 |
| `53-transparent-proxy` | `CGROUP_SOCK_ADDR` | `bpf_sock_addr` | 1=allow, 0=deny | 连接重定向 |
| `77-sock-addr-monitor` | `CGROUP_SOCK_ADDR` | `bpf_sock_addr` | 只读 | 连接监控 |
| `73-lsm-cgroup` | `LSM_CGROUP` | LSM args | 1=allow, 0=deny | socket_connect 拦截 |

> `CGROUP_SOCK`（本示例）在 socket **创建/绑定/释放** 时触发；
> `CGROUP_SOCK_ADDR`（53/77）在 socket **connect/sendmsg/recvmsg/bind** 时触发。
> 两者程序类型不同，上下文不同，触发时机不同。

## 文件结构

- `cgroup-sock.bpf.c` — 4 个 BPF 程序（sock_create, post_bind4, post_bind6, sock_release）+ ringbuf
- `cgroup-sock.c` — 用户态加载器（cgroup 创建 + attach + fork 子进程测试 + ringbuf 消费）
- `cgroup-sock.h` — 共享定义（event 结构体、常量、DEMO_CGROUP）
- `Makefile` — `APP := cgroup-sock`
