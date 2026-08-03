# 57-iter-task-file — 进程文件描述符审计

## 概述

用 `SEC("iter/task_file")` 遍历进程打开的文件，输出 tgid/pid/fd/file_ops。支持 `--pid` 参数化过滤指定进程。

## 编译与运行

```bash
make -C src/57-iter-task-file

# 遍历当前进程的文件
sudo ./src/57-iter-task-file/iter-task-file --pid $$

# 遍历所有进程的文件
sudo ./src/57-iter-task-file/iter-task-file
```

## 输出示例

```
# ./iter-task-file --pid 1
=== Files opened by PID 1 ===
tgid     pid      comm             fd       file_ops        
1        1        systemd          0        ffffaf57b0a6eda8
1        1        systemd          1        ffffaf57b0a6eda8
1        1        systemd          2        ffffaf57b0a6eda8
1        1        systemd          3        ffffaf57b0729990
1        1        systemd          4        ffffaf57b0753cb8
1        1        systemd          5        ffffaf57b0753f80

```

## 教学概念

- `SEC("iter/task_file")` + `bpf_iter__task_file` 上下文
- `bpf_iter_attach_opts` 参数化过滤（`linfo.task.pid`）
- `BPF_SEQ_PRINTF` 格式化输出到 seq_file
- 两种过滤方式对比：attach_opts（内核侧）vs 全局变量（BPF 内 if）
