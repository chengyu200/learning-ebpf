# 16-memleak（精简版）

追踪用户态内存分配，报告“未释放（outstanding）”的分配及其调用栈 Top N。

## 做什么

- 内核态：uprobe 挂 libc 的 `malloc`/`calloc`/`realloc`（uprobe+uretprobe）与 `free`（uprobe）；入口记录 size（按 pid_tgid 暂存），返回时按地址记录分配（含用户栈 id，`BPF_MAP_TYPE_STACK_TRACE`）；`free` 删除对应记录。
- 用户态：argp（`--pid` 或 `--command`、`--obj`、`-i`、`-T`），自动定位 libc，用 `bpf_program__attach_uprobe_opts(.func_name=...)` 挂载；按周期遍历 allocs 哈希表，按栈聚合后打印 Top N（栈帧以原始地址输出）。

## 教学概念

- uprobe/uretprobe 挂 libc 分配函数、`BPF_KRETPROBE` 取返回值。
- `BPF_MAP_TYPE_STACK_TRACE` + `bpf_get_stackid(BPF_F_USER_STACK)`。
- enter/exit 用哈希表传递 size；按地址追踪未释放分配。
- 用户态遍历哈希表 + 按栈聚合。

## 运行

```bash
make -C src/16-memleak
# 追踪一个命令（fork-exec 并带管道同步）：
sudo ./src/16-memleak/memleak -c "sleep 2" -i 2 -T 3
# 或追踪已运行进程：
sudo ./src/16-memleak/memleak -p <PID>
```

## 与原教程差异

原版移植自 libbpf-tools memleak（含 kmem tracepoint、combined allocs、blazesym 符号化，700+ 行用户态）。本仓库为**精简版**：仅 libc malloc/free/calloc/realloc，无内核 kmem、无 blazesym（栈以原始地址输出）。
