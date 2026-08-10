# 77-sock-addr-monitor

用 `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` 的全部 17 个挂载点审计 cgroup 内进程的 socket 地址操作。

## 什么是 BPF CGROUP_SOCK_ADDR

`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` 允许 BPF 程序拦截和改写 cgroup 内进程的 **socket 地址操作**——bind、connect、sendmsg、recvmsg、getpeername、getsockname。这是 Cilium 服务代理、Istio 透明代理等技术的底层基础。

### 上下文：`struct bpf_sock_addr`

```c
struct bpf_sock_addr {
    __u32 user_family;   // 只读：用户传入的地址族
    __u32 user_ip4;      // 可读写：IPv4 地址（网络字节序）
    __u32 user_ip6[4];   // 可读写：IPv6 地址
    __u32 user_port;     // 可读写：端口（网络字节序）
    __u32 family;        // 只读：socket 的地址族
    __u32 type;          // 只读：SOCK_STREAM / SOCK_DGRAM
    __u32 protocol;      // 只读：IPPROTO_TCP / UDP
    __u32 msg_src_ip4;   // 可读写：UDP recvmsg 源 IPv4
    __u32 msg_src_ip6[4];// 可读写：UDP recvmsg 源 IPv6
    struct bpf_sock *sk; // 只读：关联的 socket
};
```

**可写字段**（透明代理改写的关键）：`user_ip4`、`user_ip6`、`user_port`、`msg_src_ip4`、`msg_src_ip6`

### 17 个挂载点

| 操作类 | IPv4 | IPv6 | Unix | 触发时机 |
|--------|------|------|------|---------|
| **bind** | `cgroup/bind4` | `cgroup/bind6` | — | `bind()` |
| **connect** | `cgroup/connect4` | `cgroup/connect6` | `cgroup/connect_unix` | `connect()` |
| **sendmsg** | `cgroup/sendmsg4` | `cgroup/sendmsg6` | `cgroup/sendmsg_unix` | UDP `sendmsg()` |
| **recvmsg** | `cgroup/recvmsg4` | `cgroup/recvmsg6` | `cgroup/recvmsg_unix` | UDP `recvmsg()` |
| **getpeername** | `cgroup/getpeername4` | `cgroup/getpeername6` | `cgroup/getpeername_unix` | `getpeername()` |
| **getsockname** | `cgroup/getsockname4` | `cgroup/getsockname6` | `cgroup/getsockname_unix` | `getsockname()` |

### TCP vs UDP hook 差异

| Hook | TCP | UDP |
|------|-----|-----|
| bind4/6 | ✅ | ✅ |
| connect4/6/unix | ✅ | ✅ |
| sendmsg4/6/unix | ❌ | ✅ |
| recvmsg4/6/unix | ❌ | ✅ |
| getpeername4/6/unix | ✅ | ✅ |
| getsockname4/6/unix | ✅ | ✅ |

## 做什么

- 创建专用子 cgroup
- attach 全部 17 个 BPF 程序到 cgroup
- fork 子进程进入 cgroup，执行 socket 操作触发所有 hook：
  - **TCP IPv4**：bind → listen → connect → getsockname → getpeername
  - **UDP IPv4**：sendmsg → recvmsg → getsockname
  - **TCP IPv6**：同上
  - **UDP IPv6**：同上
  - **Unix socket**：connect → sendmsg → recvmsg → getpeername → getsockname
- 父进程消费 ringbuf，打印每个 hook 的事件（操作类型、地址族、socket 类型、端口、IP）

## 运行

```bash
make -C src/77-sock-addr-monitor
sudo ./src/77-sock-addr-monitor/sock-addr-monitor
```

### 输出示例

```
BPF sock_addr monitor attached to /sys/fs/cgroup/cg-sock-monitor
  17 programs attached (bind×2, connect×3, sendmsg×3, recvmsg×3, getpeername×3, getsockname×3)

BPF events:
  [BIND4       ] family=AF_INET  type=STREAM proto=TCP port=0      ip=127.0.0.1  pid=12345
  [GETSOCKNAME4] family=AF_INET  type=STREAM proto=TCP port=39197  ip=127.0.0.1  pid=12345
  [CONNECT4    ] family=AF_INET  type=STREAM proto=TCP port=39197  ip=127.0.0.1  pid=12345
  [GETPEERNAME4] family=AF_INET  type=STREAM proto=TCP port=39197  ip=127.0.0.1  pid=12345
  [GETSOCKNAME4] family=AF_INET  type=STREAM proto=TCP port=52558  ip=127.0.0.1  pid=12345
  [BIND4       ] family=AF_INET  type=DGRAM  proto=UDP port=0      ip=127.0.0.1  pid=12345
  [GETSOCKNAME4] family=AF_INET  type=DGRAM  proto=UDP port=56425  ip=127.0.0.1  pid=12345
  [SENDMSG4    ] family=AF_INET  type=DGRAM  proto=UDP port=9999   ip=127.0.0.1  pid=12345
  [SENDMSG4    ] family=AF_INET  type=DGRAM  proto=UDP port=56425  ip=127.0.0.1  pid=12345
  [RECVMSG4    ] family=AF_INET  type=DGRAM  proto=UDP port=51093  ip=127.0.0.1  pid=12345
  [BIND6       ] family=AF_INET6 type=STREAM proto=TCP port=0      ip=::1  pid=12345
  [GETSOCKNAME6] family=AF_INET6 type=STREAM proto=TCP port=34161  ip=::1  pid=12345
  [CONNECT6    ] family=AF_INET6 type=STREAM proto=TCP port=34161  ip=::1  pid=12345
  [GETPEERNAME6] family=AF_INET6 type=STREAM proto=TCP port=34161  ip=::1  pid=12345
  [GETSOCKNAME6] family=AF_INET6 type=STREAM proto=TCP port=55970  ip=::1  pid=12345
  [BIND6       ] family=AF_INET6 type=DGRAM  proto=UDP port=0      ip=::1  pid=12345
  [GETSOCKNAME6] family=AF_INET6 type=DGRAM  proto=UDP port=39856  ip=::1  pid=12345
  [SENDMSG6    ] family=AF_INET6 type=DGRAM  proto=UDP port=9999   ip=::1  pid=12345
  [SENDMSG6    ] family=AF_INET6 type=DGRAM  proto=UDP port=39856  ip=::1  pid=12345
  [RECVMSG6    ] family=AF_INET6 type=DGRAM  proto=UDP port=57101  ip=::1  pid=12345
  [CONNECT_UNIX] family=AF_UNIX  type=STREAM proto=-   port=0      ip=-  pid=12345
  [GETPEER_UNX ] family=AF_UNIX  type=STREAM proto=-   port=0      ip=-  pid=12345
  [GETSOCK_UNX ] family=AF_UNIX  type=STREAM proto=-   port=0      ip=-  pid=12345
  [SENDMSG_UNIX] family=AF_UNIX  type=DGRAM  proto=-   port=0      ip=-  pid=12345
  [RECVMSG_UNIX] family=AF_UNIX  type=DGRAM  proto=-   port=0      ip=-  pid=12345
  [GETSOCK_UNX ] family=AF_UNIX  type=DGRAM  proto=-   port=0      ip=-  pid=12345

All socket operations demonstrated.
```

> 注：事件可能在子进程操作完成后才被父进程 poll 到，因此输出顺序可能与操作顺序不完全一致。Unix socket 客户端需要显式 `bind()` 到 abstract name，否则 `getsockname_unix` hook 不会触发（内核 `unix_getname()` 在 `addr==NULL` 时跳过 BPF hook）。

## 教学概念

| 概念 | 说明 |
|------|------|
| `SEC("cgroup/bind4")` 等 17 种 | 每种对应的 socket 操作 |
| `bpf_sock_addr` 上下文 | `user_ip4`/`user_port` 可读写，`family`/`type`/`protocol` 只读 |
| `user_family` vs `family` | 前者是用户传入的地址族，后者是 socket 的地址族 |
| `msg_src_ip4` | UDP recvmsg 专用：收到的包的源地址（可改写） |
| 返回值 `1`/`0` | `1` = 允许操作，`0` = 拒绝（阻止操作） |
| TCP vs UDP | sendmsg/recvmsg 只对 UDP 触发；connect 对 TCP+UDP 触发 |
| IPv4 vs IPv6 vs Unix | IPv4 用 `user_ip4`，IPv6 用 `user_ip6[4]`，Unix 无 IP/端口 |
| `bpf_program__attach_cgroup` | 通用 cgroup attach API（17 个程序都用此 API） |

## 技术细节

### 可写字段与透明代理

`bpf_sock_addr` 的 `user_ip4`、`user_port` 等字段可写，这就是透明代理的工作原理：

```c
SEC("cgroup/connect4")
int redirect(struct bpf_sock_addr *ctx) {
    if (bpf_ntohs(ctx->user_port) == 8080) {
        ctx->user_port = bpf_htons(15006);  // 改写目的端口到 sidecar
    }
    return 1;  // 允许连接（到改写后的地址）
}
```

对应的 `getpeername4` 可以改写回原始端口，让客户端以为在连 8080：

```c
SEC("cgroup/getpeername4")
int restore(struct bpf_sock_addr *ctx) {
    ctx->user_port = bpf_htons(8080);  // 改回原始端口
    return 1;
}
```

仓库中的 `53-transparent-proxy` 示例完整演示了这一改写流程。

### sendmsg/recvmsg 的 msg_src 字段

UDP `sendmsg` 时，`user_ip4`/`user_port` 是目的地址（可改写）。UDP `recvmsg` 时，`msg_src_ip4` 是收到的包的源地址（可改写），用于伪装来源。

**重要**：RECVMSG hook（`cgroup/recvmsg4` 等）仅在 `recvfrom`/`recvmsg` 调用者**请求源地址**（`msg_name != NULL`）时才触发。如果调用 `recvfrom(fd, buf, len, 0, NULL, NULL)`（不关心源地址），hook 不会触发。

```c
/* ✅ 触发 RECVMSG hook */
struct sockaddr_in src;
socklen_t slen = sizeof(src);
recvfrom(fd, buf, len, 0, (struct sockaddr *)&src, &slen);

/* ❌ 不触发 RECVMSG hook */
recvfrom(fd, buf, len, 0, NULL, NULL);
```

### Unix socket 的特殊性

Unix socket 没有 IP 地址和端口号，`bpf_sock_addr` 中的 `user_ip4`/`user_port` 不适用。Unix socket 的路径信息不在 `bpf_sock_addr` 上下文中（需要通过 `sk` 指针间接访问）。

**重要**：`getsockname_unix` / `getpeername_unix` hook 仅在 socket **已绑定地址**（`addr != NULL`）时才触发。内核源码 `net/unix/af_unix.c` 中的 `unix_getname()` 函数：

```c
addr = smp_load_acquire(&unix_sk(sk)->addr);
if (!addr) {
    // addr == NULL：直接返回默认地址，不调用 BPF hook
    sunaddr->sun_family = AF_UNIX;
    sunaddr->sun_path[0] = 0;
    err = offsetof(struct sockaddr_un, sun_path);
} else {
    // addr != NULL：复制地址，然后调用 BPF hook
    memcpy(sunaddr, addr->name, addr->len);
    BPF_CGROUP_RUN_SA_PROG(..., CGROUP_UNIX_GETSOCKNAME);  // ← 只在这里
}
```

如果客户端 socket 没有显式 `bind()`，它的 `addr` 为 NULL，`getsockname` 不会触发 BPF hook。解决方法是显式 `bind()` 到一个 abstract name：

```c
struct sockaddr_un ubind = { .sun_family = AF_UNIX };
ubind.sun_path[0] = 0;  // abstract namespace（第一个字节为 0）
ubind.sun_path[1] = 'c';
bind(fd, &ubind, sizeof(ubind));  // 现在 addr != NULL，getsockname 会触发
```

## 与现有示例的对比

| 示例 | 程序类型 | SEC | 作用 |
|------|---------|-----|------|
| 51-cgroup-sysctl | CGROUP_SYSCTL | cgroup/sysctl | 审计 sysctl 读写 |
| 53-transparent-proxy | CGROUP_SOCK_ADDR | cgroup/connect4 | **改写** connect 目的端口 |
| 73-lsm-cgroup | LSM | lsm_cgroup/socket_connect | 安全策略 |
| 76-cgroup-device | CGROUP_DEVICE | cgroup/dev | 设备白名单 |
| **77-sock-addr-monitor** | **CGROUP_SOCK_ADDR** | **17 种** | **审计全 17 种 socket 地址操作** |

## 文件结构

```
77-sock-addr-monitor/
├── Makefile                  # APP := sock-addr-monitor
├── sock-addr-monitor.h        # 共享：event 结构、op_type 枚举
├── sock-addr-monitor.bpf.c    # 17 个 BPF 程序 + 共享 log_event()
├── sock-addr-monitor.c        # 加载器 + cgroup + 子进程测试
└── README.md
```
