# 80-cgroup-sockopt

用 `BPF_PROG_TYPE_CGROUP_SOCKOPT` 实现 socket 选项防火墙 + 审计器：禁止修改 `SO_REUSEADDR`、审计所有选项操作、透明改写 `IP_TTL`。

## 什么是 BPF CGROUP_SOCKOPT

`BPF_PROG_TYPE_CGROUP_SOCKOPT` 允许 BPF 程序拦截和改写 cgroup 内进程的 `getsockopt`/`setsockopt` 系统调用。可以用于安全策略（禁止修改关键选项）、审计 socket 选项使用、或透明改写选项值。

### 上下文：`struct bpf_sockopt`

```c
struct bpf_sockopt {
    struct bpf_sock *sk;       // 关联的 socket
    void *optval;              // 选项值缓冲区指针
    void *optval_end;          // 缓冲区末尾（边界检查）
    __s32 level;               // SOL_SOCKET / SOL_IP / SOL_TCP
    __s32 optname;             // SO_REUSEADDR / IP_TTL / TCP_NODELAY
    __s32 optlen;              // 选项值长度（可改写）
    __s32 retval;              // 返回值（getsockopt 可设置）
};
```

### 两个挂载点

| SEC | attach_type | 触发时机 | BPF 运行顺序 | 返回值语义 |
|-----|------------|---------|-------------|-----------|
| `cgroup/setsockopt` | `BPF_CGROUP_SETSOCKOPT` | `setsockopt()` | 内核 setsockopt **之前** | `1` = ALLOW，`0` = DENY (EPERM) |
| `cgroup/getsockopt` | `BPF_CGROUP_GETSOCKOPT` | `getsockopt()` | 内核 getsockopt **之后** | `1` = ALLOW，`0` = DENY (EPERM) |

**关键区别**：setsockopt 的 BPF 在内核处理**之前**运行（可以选择跳过内核）；getsockopt 的 BPF 在内核处理**之后**运行（可以读取和改写内核返回的值）。

### 返回值语义（内核源码分析）

返回值语义来自内核源码 `kernel/bpf/cgroup.c` 的 `bpf_prog_run_array_cg` 函数：

```c
run_ctx.retval = retval;  // 初始化为 0（setsockopt）或内核返回值（getsockopt）
while ((prog = ...)) {
    func_ret = run_prog(prog, ctx);     // BPF 程序返回值
    func_ret &= 1;                      // 只取 bit 0
    if (!func_ret && !IS_ERR_VALUE((long)run_ctx.retval))
        run_ctx.retval = -EPERM;        // return 0 → 强制设为 -EPERM
}
return run_ctx.retval;
```

关键逻辑：`return 0` 会将 `retval` **强制设为** `-EPERM`，而 `return 1` 不改变 `retval`。

`bpf_set_retval` 的作用是设置 `run_ctx.retval`，但只有 `return 1` 时设置的值才会保留（因为 `return 0` 会覆盖它）：

| BPF return | bpf_set_retval | 结果 | 说明 |
|-----------|---------------|------|------|
| `1` | 不调用 | **ALLOW** (retval=0) | 成功 |
| `1` | `-EPERM` | **DENY** (retval=-EPERM) | 拒绝，调用者收到 EPERM |
| `1` | `-ENOMEM` | **DENY** (retval=-ENOMEM) | 拒绝，调用者收到 ENOMEM |
| `0` | 任何值 | **DENY** (retval=-EPERM) | return 0 覆盖 retval 为 -EPERM |

`run_ctx` 是栈上的局部变量，每次 `bpf_prog_run_array_cg` 调用时重新初始化，**不会在系统调用间渗透**。

### 与其他 cgroup BPF 类型的对比

| 类型 | SEC | 作用 | 返回值 |
|------|-----|------|--------|
| `CGROUP_SKB` | `cgroup_skb/egress` | 过滤网络包 | 1=allow, 0=deny |
| `CGROUP_SYSCTL` | `cgroup/sysctl` | 拦截 sysctl 读写 | 1=allow, 0=deny |
| `CGROUP_DEVICE` | `cgroup/dev` | 控制设备访问 | 1=allow, 0=deny |
| `CGROUP_SOCK_ADDR` | `cgroup/connect4` 等 | 拦截 socket 地址操作 | 1=allow, 0=deny |
| **`CGROUP_SOCKOPT`** | **`cgroup/getsockopt`** | **审计/改写 getsockopt** | **1=ALLOW, 0=DENY** |
| **`CGROUP_SOCKOPT`** | **`cgroup/setsockopt`** | **审计/阻止 setsockopt** | **1=ALLOW, 0=DENY** |

## 做什么

- 创建专用子 cgroup
- **setsockopt 防火墙**：禁止 cgroup 内进程修改 `SO_REUSEADDR`（安全策略，防止端口劫持）
- **getsockopt 审计 + 改写**：记录所有 getsockopt 调用，读取 `IP_TTL` 时强制返回 `64`
- fork 子进程进入 cgroup，测试：
  1. `setsockopt(SO_REUSEADDR)` → **EPERM**（被 BPF 拒绝）
  2. `setsockopt(SO_KEEPALIVE)` → **成功**（BPF 放行）
  3. `getsockopt(SO_TYPE)` → **成功**（审计记录）
  4. `getsockopt(IP_TTL)` → **返回 64**（BPF 改写）

## 运行

```bash
make -C src/80-cgroup-sockopt
sudo ./src/80-cgroup-sockopt/cgroup-sockopt
```

### 输出示例

```
BPF cgroup/sockopt firewall attached to /sys/fs/cgroup/cg-sockopt-demo
  setsockopt: BLOCK SO_REUSEADDR, AUDIT all others
  getsockopt: AUDIT all, REWRITE IP_TTL→64

Child (in cgroup) testing:
  [child] moved into cgroup (pid=12345)

  [child] test 1: setsockopt SO_REUSEADDR...
  [child] PASS: SO_REUSEADDR blocked (Operation not permitted)

  [child] test 2: setsockopt SO_KEEPALIVE...
  [child] PASS: SO_KEEPALIVE allowed (OK)

  [child] test 3: getsockopt SO_TYPE...
  [child] PASS: SO_TYPE = 1 (allowed)

  [child] test 4: getsockopt IP_TTL...
  [child] PASS: IP_TTL = 64 (rewritten by BPF)

BPF events:
  [SET] level=1 optname=2  (SO_REUSEADDR  ) optlen=4  BLOCKED    pid=12345
  [SET] level=1 optname=9  (SO_KEEPALIVE  ) optlen=4  allowed    pid=12345
  [GET] level=1 optname=3  (SO_TYPE       ) optlen=4  allowed    pid=12345
  [GET] level=0 optname=2  (IP_TTL        ) optlen=4  rewritten→64  pid=12345
```

## 教学概念

| 概念 | 说明 |
|------|------|
| `SEC("cgroup/setsockopt")` | 拦截 setsockopt 调用（内核处理之前） |
| `SEC("cgroup/getsockopt")` | 拦截 getsockopt 调用（内核处理之后） |
| `bpf_sockopt` 上下文 | `level`/`optname`/`optlen`/`optval`/`optval_end`/`retval` |
| `optval`/`optval_end` | 选项值缓冲区（边界检查模式类似 TC 的 `data`/`data_end`） |
| 返回值 | `1`=ALLOW, `0`=DENY（EPERM） |
| `bpf_set_retval` | 设置 retval，配合 `return 1` 返回特定 errno |
| getsockopt 改写 | 修改 `optval` 内容 + 设置 `ctx->optlen` |
| `bpf_program__attach_cgroup` | 通用 cgroup attach API |

## 技术细节

### setsockopt 与 getsockopt 的运行时序

```
setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, len)
  │
  ├─ BPF cgroup/setsockopt（内核处理之前）
  │    return 1 + bpf_set_retval(-EPERM) → DENY（直接返回 EPERM）
  │    return 1（retval=0）→ 继续
  │      ctx.optlen == -1 → 跳过内核 setsockopt（BPF 完全处理）
  │      ctx.optlen >= 0  → 内核正常处理 setsockopt
  │
  └─ 内核 setsockopt

getsockopt(fd, SOL_IP, IP_TTL, &val, &len)
  │
  ├─ 内核 getsockopt（先执行，结果写入 optval/optlen）
  │
  └─ BPF cgroup/getsockopt（内核处理之后）
       可以读取内核返回的 optval（检查/审计）
       可以改写 optval + optlen（透明改写）
       return 1（retval=0）→ ALLOW，optval/optlen 复制给用户
       return 0 → DENY（EPERM）
```

关键区别：
- **setsockopt**：BPF 在内核**之前**运行，可以选择跳过内核（`ctx.optlen = -1`）
- **getsockopt**：BPF 在内核**之后**运行，可以读取和改写内核返回的值，没有跳过内核的机制

### setsockopt 防火墙

```c
SEC("cgroup/setsockopt")
int cg_setsockopt(struct bpf_sockopt *ctx) {
    if (ctx->level == SOL_SOCKET && ctx->optname == SO_REUSEADDR) {
        bpf_set_retval(-EPERM);  /* 设置 errno = EPERM */
        return 1;                /* retval=-EPERM → DENY */
    }
    return 1;  /* retval=0 → ALLOW，内核继续处理 setsockopt */
}
```

setsockopt 的 `__cgroup_bpf_run_filter_setsockopt` 在 `bpf_prog_run_array_cg` 返回后：
- `ret == 0`（BPF return 1，retval=0）→ 继续处理（根据 `ctx.optlen` 决定是否调用内核 setsockopt）
- `ret < 0`（BPF return 0，或 bpf_set_retval(-EPERM) + return 1）→ 返回错误给调用者

### getsockopt 透明改写

```c
SEC("cgroup/getsockopt")
int cg_getsockopt(struct bpf_sockopt *ctx) {
    if (ctx->level == SOL_IP && ctx->optname == IP_TTL) {
        __u32 *optval = ctx->optval;
        __u32 *optval_end = ctx->optval_end;

        /* 边界检查（类似 TC 的 data/data_end） */
        if ((void *)(optval + 1) <= (void *)optval_end) {
            *optval = 64;       /* 改写内核返回的 TTL 值 */
            ctx->optlen = 4;    /* 设置返回长度 */
        }
    }
    return 1;  /* retval=0 → ALLOW，改写后的 optval/optlen 复制给用户 */
}
```

getsockopt 的 `__cgroup_bpf_run_filter_getsockopt` 在 `bpf_prog_run_array_cg` 返回后：
- `ret < 0`（BPF return 0，或 bpf_set_retval(-EPERM) + return 1）→ 返回错误给调用者
- `ret >= 0`（BPF return 1，retval=0）→ 如果 `ctx.optlen != 0`，将 BPF 的 `optval`/`optlen` 复制给用户

关键点：
1. **BPF 在内核 getsockopt 之后运行**：BPF 可以读取内核返回的 optval（审计），也可以改写它（透明改写）
2. **边界检查**：写 `optval` 前必须检查 `optval + sizeof(type) <= optval_end`，否则验证器拒绝
3. **设置 optlen**：改写后必须更新 `ctx->optlen`，否则调用者可能读到错误的长度
4. **return 1**：表示 ALLOW，改写后的 `optval`/`optlen` 会复制给用户

### optval/optval_end 边界检查

与 TC/XDP 的 `data`/`data_end` 模式完全相同：

```c
/* TC */
void *data = (void *)(long)skb->data;
void *data_end = (void *)(long)skb->data_end;
if (data + sizeof(struct ethhdr) > data_end) return;

/* CGROUP_SOCKOPT */
void *optval = ctx->optval;
void *optval_end = ctx->optval_end;
if (optval + sizeof(__u32) > optval_end) return;
```

## 文件结构

```
80-cgroup-sockopt/
├── Makefile              # APP := cgroup-sockopt
├── cgroup-sockopt.h        # 共享：event 结构、SOL_*/SO_* 常量
├── cgroup-sockopt.bpf.c    # 2 个 BPF 程序
├── cgroup-sockopt.c        # 加载器 + cgroup + 子进程测试
└── README.md
```
