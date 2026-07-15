# learning-ebpf

基于 **libbpf + C 语言** 的 eBPF 入门示例仓库。参考 [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 的 “入门示例 (Getting Started)” 部分（lesson 1–10），将其中的 eunomia-bpf 框架全部改写为 **libbpf + CO-RE** 的实现方式，每个示例都自包含、可独立编译运行。

> CO-RE（Compile Once, Run Everywhere）：借助 BTF 与 libbpf 骨架（skeleton），eBPF 程序编译一次即可在任意版本的内核上运行，无需为每个内核单独编译。

## 示例索引

每个目录是一个独立示例，由 `.bpf.c`（内核态）+ `.c`（用户态）+ `.h`（共享结构）+ `Makefile` + `README.md` 组成。

| # | 示例 | 教学概念 | 挂载类型 | 数据通道 |
|---|------|---------|---------|---------|
| 1 | [helloworld](src/1-helloworld) | 最小骨架流程、trace_pipe 调试 | tracepoint | `bpf_trace_printk` |
| 2 | [kprobe-unlink](src/2-kprobe-unlink) | kprobe、`BPF_KPROBE`、读内核结构体 | kprobe | ringbuf |
| 3 | [fentry-unlink](src/3-fentry-unlink) | fentry(BTF)、与 kprobe 对比 | fentry | ringbuf |
| 4 | [opensnoop](src/4-opensnoop) | 全局变量过滤、enter/exit 哈希匹配 | tracepoint | ringbuf |
| 5 | [uprobe-bashreadline](src/5-uprobe-bashreadline) | uprobe / uretprobe 用户态函数 | uretprobe | ringbuf |
| 6 | [sigsnoop](src/6-sigsnoop) | 哈希表保存状态、多个 tracepoint | tracepoint | ringbuf |
| 7 | [execsnoop](src/7-execsnoop) | **perf event array** 输出 | tracepoint | perf_buffer |
| 8 | [exitsnoop](src/8-exitsnoop) | **ring buffer** 输出、fork+exit 追踪 | tracepoint | ringbuf |
| 9 | [runqlat](src/9-runqlat) | log2 直方图、array map | tracepoint | array map 轮询 |
| 10 | [hardirqs](src/10-hardirqs) | 中断追踪、per-cpu 哈希累加 | tracepoint | hash map 遍历 |

设计上刻意让 **2↔3**（kprobe vs fentry）、**7↔8**（perf_buffer vs ringbuf）形成对照，覆盖 libbpf 的全部主流 map 类型与挂载类型。

## 高级示例（lessons 11–21）

基于 libbpf + C 的完整项目实践（原教程“高级示例”，lesson 11–21）。其中 12-profile 原为 Rust、15/19/20/21 原为 eunomia，均改写为 libbpf + C。

| # | 示例 | 教学概念 | 挂载/通道 |
|---|------|---------|---------|
| 11 | [bootstrap](src/11-bootstrap) | 完整骨架生命周期、exec/exit、argp | tracepoint / ringbuf |
| 12 | [profile](src/12-profile) | perf_event 采样 profiling、`bpf_get_stack`、`/proc/kallsyms` 符号化 | perf_event / ringbuf |
| 13 | [tcpconnlat](src/13-tcpconnlat) | TCP connect 延迟 | kprobe / perf_array |
| 14 | [tcpstates](src/14-tcpstates) | TCP 状态变迁与停留时长 | tracepoint / perf_array |
| 15 | [javagc](src/15-javagc) | USDT 探针（HotSpot GC） | usdt / perf_array |
| 16 | [memleak](src/16-memleak) | 内存泄漏追踪（精简版：libc malloc/free + 栈） | uprobe / hash + stack_trace |
| 17 | [biopattern](src/17-biopattern) | 随机/顺序 I/O 统计 | tracepoint / hash |
| 18 | [further-reading](src/18-further-reading) | 进阶参考资料索引（无代码） | — |
| 19 | [lsm-connect](src/19-lsm-connect) | BPF LSM 安全拦截 connect | lsm / trace_pipe |
| 20 | [tc](src/20-tc) | tc 流量控制（clsact ingress） | tc / trace_pipe |
| 21 | [xdp](src/21-xdp) | XDP 高性能包处理 | xdp / trace_pipe |

> 环境受限说明：
> - **15-javagc**：本机无 Java，仅编译通过，运行需 JVM。
> - **19-lsm-connect**：`bpf` 不在活跃 LSM 列表，仅编译通过，运行需 `lsm=...,bpf` 重启。
> - **20-tc / 21-xdp**：用 `scripts/setup-veth.sh` 建 veth 对（带 netns）做安全测试。

## 依赖

- `clang`、`llvm`（含 `llvm-strip`）、`make`
- `libelf`（`libelf-dev`）、`zlib`（`zlib1g-dev`）、`libssl-dev`（bpftool 构建）
- 网络：`iproute2`（`ip`/`tc`，仅 tc/xdp 示例需要）
- 内核启用 `CONFIG_BPF_SYSCALL` 与 `CONFIG_DEBUG_INFO_BTF`（本仓库用 `bpftool btf dump` 从运行内核 `/sys/kernel/btf/vmlinux` 生成 `vmlinux.h`）

安装（Debian/Ubuntu）：

```bash
make install
```

## 编译

```bash
# 1. 同步子模块（libbpf 与 bpftool）
git submodule update --init --recursive

# 2. 编译全部示例（首次会自动构建 libbpf.a、bpftool 并生成 vmlinux.h）
make
```

`make` 的工作流程：
1. 在 `.build/` 下一次性构建 `libbpf.a` 与 `bpftool`（各示例共享，避免重复编译）；
2. 由运行内核的 BTF 生成 `vmlinux/<arch>/vmlinux.h`；
3. 遍历 `src/*/`：`*.bpf.c` → `*.bpf.o`（clang -target bpf）→ `*.skel.h`（bpftool gen skeleton）→ 链接用户态二进制。

也可单独编译某个示例：

```bash
make -C src/4-opensnoop
```

清理：

```bash
make clean
```

## 运行

eBPF 程序需要 root 权限加载：

```bash
sudo ./src/2-kprobe-unlink/kprobe-unlink
# 另开终端：rm /tmp/foo 触发
```

更多触发方式见各示例的 `README.md`。

## 目录结构

```
learning-ebpf/
├── Makefile            # 顶层：构建 libbpf/bpftool、生成 vmlinux.h、遍历示例
├── common.mk          # 各示例共享的编译规则（被 src/*/Makefile include，含 libbpf/bpftool/vmlinux 构建）
├── libbpf/            # git submodule
├── bpftool/           # git submodule
├── vmlinux/<arch>/    # 由内核 BTF 生成（.gitignore 忽略）
├── .build/            # 共享构建产物（.gitignore 忽略）
├── scripts/setup-veth.sh   # 建 veth+netns 供 tc/xdp 测试
├── src/common/        # 共享 BPF 辅助头（maps.bpf.h）
└── src/1-helloworld … 21-xdp/
```

## 与原教程的差异

- 原教程 lesson 1–10 使用 `eunomia-bpf` 框架；本仓库全部改为 `libbpf` + 骨架（skeleton）+ CO-RE。
- `vmlinux.h` 从运行内核实时生成，而非使用预编译版本，保证与本机内核严格匹配。
- lesson 2/3 原教程挂钩 `do_unlinkat`，该函数在本机内核（7.0）已被内联移除，故改挂 `vfs_unlink` 并从 `dentry->d_name.name` 读取文件名。

## License

LGPL-2.1 OR BSD-2-Clause
