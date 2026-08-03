# 61-iter-pin — Pin 到 bpffs + cat 读取

## 概述

演示 `bpftool iter pin` + `cat` 工作流：将 BPF iterator 程序 pin 到 bpffs，用 `cat` 读取输出，类似 `/proc` 文件。

此示例**只需要 .bpf.o 文件**，不需要用户态程序。用 `bpftool` 命令完成 attach 和读取。

## 编译与运行

```bash
# 编译（只生成 .bpf.o，不生成 skeleton/用户态二进制）
make -C src/61-iter-pin

# pin 到 bpffs
sudo bpftool iter pin ./src/61-iter-pin/iter-pin.bpf.o /sys/fs/bpf/my_task_iter

# cat 读取（触发遍历）
cat /sys/fs/bpf/my_task_iter

# 清理
rm /sys/fs/bpf/my_task_iter
```

## 输出示例

```bash
# cat /sys/fs/bpf/my_task_iter 
tgid     pid      comm            
1        1        systemd         
2        2        kthreadd        
3        3        pool_workqueue_ 
4        4        kworker/R-rcu_g 
5        5        kworker/R-sync_ 
6        6        kworker/R-kvfre 
7        7        kworker/R-slub_ 
8        8        kworker/R-netns 
10       10       kworker/0:0H    
13       13       kworker/R-mm_pe 
14       14       ksoftirqd/0     
15       15       rcu_preempt     
16       16       rcu_exp_par_gp_ 
17       17       rcu_exp_gp_kthr 
18       18       migration/0     
19       19       idle_inject/0   
20       20       cpuhp/0         
21       21       cpuhp/1   
...
```

## 工作流对比

| 方式 | 优点 | 缺点 |
|---|---|---|
| **bpftool pin + cat** | 无需用户态程序，简单直观 | 只能文本输出，无参数化 |
| **libbpf attach_iter + read** | 可参数化，可二进制输出 | 需编写用户态代码 |

## 教学概念

- `bpftool iter pin` — 将 iterator 程序 pin 到 bpffs
- `cat /sys/fs/bpf/<name>` — 触发遍历，输出 seq_file 内容
- bpffs（BPF 文件系统）的 pin 机制
- 与 `/proc` 系统的对比：BPF iterator 是可编程的 `/proc`
- 此示例 Makefile 特殊：只编译 .bpf.o，不生成 skeleton（覆盖 common.mk 的 all 目标）
