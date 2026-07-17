# 深入主题学习路线

本仓库的深入主题部分共 30 个可运行示例 + 6 个 README 占位（不可行项）。建议按以下 **6 个阶段** 循序渐进学习，每个阶段建立在前一阶段的概念之上。

> **前置条件**：先完成入门（lesson 1–10）和高级（lesson 11–21），掌握 libbpf 骨架流程、kprobe/fentry、ringbuf/perf_buffer、uprobe、tracepoint、array/hash map 等基础概念。

---

## 阶段 1：追踪进阶（巩固基础，学习新技巧）

这三个示例与入门示例概念最接近，但引入了新的追踪技巧，适合作为深入主题的入口。

| 顺序 | 示例 | 前置知识 | 新学什么 |
|------|------|---------|---------|
| 1 | [33-funclatency](src/33-funclatency) | lesson 2 kprobe + lesson 9 直方图 | **通用函数延迟工具**：用 `bpf_program__attach_kprobe` 指定任意函数名，kprobe+kretprobe 配对测量延迟，`log2l` 分桶 |
| 2 | [28-detach](src/28-detach) | lesson 1 骨架流程 | **程序生命周期**：link/map pinning 到 `/sys/fs/bpf/`，程序在 loader 退出后继续运行 |
| 3 | [34-syscall](src/34-syscall) | lesson 4 enter/exit 配对 | **系统调用参数检查与修改**：tracepoint 检查 openat 参数，`bpf_override_return` 拒绝调用（需 `CONFIG_BPF_KPROBE_OVERRIDE`） |

**学完本阶段你应掌握**：如何把 BPF 程序从"一次性运行"变成"持久化服务"，以及如何用 BPF 主动干预系统调用行为。

---

## 阶段 2：用户态追踪（uprobe 渐进）

从最简单的 uprobe 开始，逐步追踪更复杂的用户态程序。每个示例增加一层复杂度。

| 顺序 | 示例 | 追踪目标 | 新学什么 |
|------|------|---------|---------|
| 4 | [38-btf-uprobe](src/38-btf-uprobe) | libc `malloc` | **最简单的 uprobe**：挂共享库函数，CO-RE 对用户态的适用性 |
| 5 | [37-uprobe-rust](src/37-uprobe-rust) | Rust 程序 `slow_function` | **不同语言的二进制**：Rust `extern "C"` 符号、偏移量定位 |
| 6 | [30-sslsniff](src/30-sslsniff) | libssl `SSL_read`/`SSL_write` | **实战 TLS 明文捕获**：uprobe+uretprobe 配对、用户态缓冲区读取 |
| 7 | [31-goroutine](src/31-goroutine) | Go 运行时 `runtime.newproc` | **语言运行时追踪**：Go 编译、符号表、goroutine 生命周期 |
| 8 | [39-nginx](src/39-nginx) | nginx `ngx_http_process_request` | **真实应用追踪**：入口+返回配对测量请求处理耗时 |
| 9 | [40-mysql](src/40-mysql) | mysqld `dispatch_command`（仅编译） | **概念了解**：数据库查询追踪的思路（无 mysqld 环境） |

**学完本阶段你应掌握**：uprobe 挂载到任意用户态函数（从 C 库到 Rust/Go/nginx/MySQL），读取参数和返回值，测量函数耗时。

---

## 阶段 3：安全攻防（BPF 的黑暗面）

按"从观察到干预"的顺序学习，逐步深入对用户态数据的操控。

| 顺序 | 示例 | 安全概念 | 新学什么 |
|------|------|---------|---------|
| 10 | [25-signal](src/25-signal) | 主动防御 | **bpf_send_signal**：在 execve 时检测恶意进程并 SIGKILL |
| 11 | [24-hide](src/24-hide) | 隐藏 | **getdents64 缓冲区遍历**：操控目录列表，隐藏指定文件 |
| 12 | [26-sudo](src/26-sudo) | 检测 | **read 缓冲区检查**：检测 passwd 风格的文件读取 |
| 13 | [27-replace](src/27-replace) | 篡改 | **bpf_probe_write_user**：透明替换文件读取内容（最危险的操作） |

> ⚠️ 安全示例演示了 BPF 的攻击能力，仅用于学习防御。`bpf_probe_write_user` 需要特权，可能破坏系统行为，请在测试环境运行。

**学完本阶段你应掌握**：BPF 如何读取/修改用户态内存，以及为什么 BPF 需要 CAP_BPF 权限限制。

---

## 阶段 4：网络进阶（从 XDP 到 sockops）

按"从早到晚"的网络栈路径学习：XDP（最早）→ socket filter → TCX → sockops（最晚）。

| 顺序 | 示例 | 网络栈位置 | 新学什么 |
|------|------|-----------|---------|
| 14 | [41-xdp-tcpdump](src/41-xdp-tcpdump) | XDP（驱动层，最早） | **XDP 包解析**：以太网/IP/TCP 头解析，五元组捕获 |
| 15 | [46-xdp-test](src/46-xdp-test) | XDP | **XDP 吞吐测量**：per-cpu array 计数 |
| 16 | [42-xdp-loadbalancer](src/42-xdp-loadbalancer) | XDP | **XDP 包重写+转发**：IP/MAC 重写、`bpf_redirect_peer`、校验和增量更新 |
| 17 | [23-http](src/23-http) | socket filter（链路层） | **raw packet socket**：`AF_PACKET` + `SO_ATTACH_BPF`、`bpf_skb_load_bytes` |
| 18 | [50-tcx](src/50-tcx) | TCX（tc 子系统） | **TCX 可组合挂载**：`bpf_program__attach_tcx`，无需手动建 qdisc |
| 19 | [29-sockops](src/29-sockops) | sockops+sk_msg（socket 层） | **sockhash 重定向**：sockops 填表 + sk_msg 绕过 TCP/IP 栈直接转发 |

**学完本阶段你应掌握**：从 XDP（驱动层）到 sockops（socket 层）的全栈 BPF 网络编程，包括包解析、重写、转发和 socket 级加速。

---

## 阶段 5：新内核特性（前沿 map/程序类型）

按"从简单到复杂"的顺序学习 6.x/7.x 内核引入的新 BPF 特性。

| 顺序 | 示例 | 特性 | 新学什么 |
|------|------|------|---------|
| 20 | [35-user-ringbuf](src/35-user-ringbuf) | `USER_RINGBUF` | **用户态→内核异步通信**：`bpf_user_ringbuf_drain` |
| 21 | [features/dynptr](src/features/dynptr) | 动态指针 | **变长数据处理**：`bpf_dynptr_from_mem`/`read`/`write` |
| 22 | [features/bpf_iters](src/features/bpf_iters) | BPF 迭代器 | **内核数据导出**：`SEC("iter/task")`、seq_file 输出 |
| 23 | [features/bpf_arena](src/features/bpf_arena) | arena map | **零拷贝共享内存**：内核与用户态共享页 |
| 24 | [features/struct_ops](src/features/struct_ops) | struct_ops | **扩展内核子系统**：用 BPF 实现 TCP 拥塞控制接口 |
| 25 | [features/bpf_wq](src/features/bpf_wq) | BPF workqueue | **异步延迟任务**：`bpf_wq_start`/`set_callback`（需 6.10+） |
| 26 | [features/bpf_token](src/features/bpf_token) | BPF token | **委托权限**：非特权 BPF 加载的安全模型 |

**学完本阶段你应掌握**：eBPF 生态的最新能力，理解每种新 map/程序类型解决什么问题。

---

## 阶段 6：综合实战

| 顺序 | 示例 | 综合运用 |
|------|------|---------|
| 27 | [43-kfuncs](src/43-kfuncs) | **最复杂示例**：内核模块注册自定义 kfunc + BPF `__ksym` 调用。融合内核开发与 BPF |
| 28 | [49-hid](src/49-hid) | HID 设备追踪，kprobe on `hidraw_report_event` |
| 29 | [cgroup](src/cgroup) | cgroup_skb 程序，cgroup 级网络策略 |

---

## 仅阅读了解（无运行环境）

| 示例 | 原因 | 学什么概念 |
|------|------|-----------|
| [22-android](src/22-android) | 非 Android | Android 上 eBPF 的加载方式（bpfloader） |
| [36-userspace-ebpf](src/36-userspace-ebpf) | 需 bpftime | 用户态 eBPF 运行时（降低 uprobe 开销） |
| [44-scx-simple](src/44-scx-simple) | sched_ext 未启用 | BPF 调度器（sched_ext） |
| [45-scx-nest](src/45-scx-nest) | 同上 | scx_nest 调度策略 |
| [47-cuda-events](src/47-cuda-events) | 无 GPU | 用 uprobe 追踪 CUDA 运行时 |
| [xpu/](src/xpu) | 无 GPU/NPU | GPU 火焰图、GPU/NPU 驱动追踪 |
| [48-energy](src/48-energy) | 无 powercap | 进程级能耗监控（RAPL） |

---

## 学习建议

1. **每阶段做笔记**：记录"这个示例用了什么 map 类型、什么挂载点、什么数据通道"。
2. **对比相邻示例**：阶段 2 中的 uprobe 示例逐步加深；阶段 4 中的网络示例按网络栈顺序排列——对比差异是最佳学习方式。
3. **修改参数实验**：每个示例都支持命令行参数，尝试改目标函数/PID/网卡名，观察行为变化。
4. **阶段 5 可选**：新特性示例部分依赖很新的内核，如果遇到加载失败属正常——理解概念即可。
5. **43-kfuncs 放最后**：它需要构建内核模块，是整个仓库中最复杂的示例，建议在前 5 个阶段都完成后再挑战。
