# 59-iter-vma — VMA 虚拟内存区域遍历

## 概述

用 `SEC("iter/task_vma")` 遍历进程的虚拟内存区域（VMA），输出 pid + 地址范围 + 权限。类似 `/proc/<pid>/maps`，但用 BPF iterator 实现。

## 编译与运行

```bash
make -C src/59-iter-vma

# 遍历当前进程的 VMA
sudo ./src/59-iter-vma/iter-vma --pid $$

# 遍历所有进程的 VMA
sudo ./src/59-iter-vma/iter-vma
```

## 输出示例

```
=== VMAs of PID 278306 ===
pid      start              end                perms
278306   c704f99c0000       c704f9b2f000       r-xp
278306   c704f9b3c000       c704f9b40000       r--p
278306   c704f9b40000       c704f9b49000       rw-p
...
```

## 教学概念

- `SEC("iter/task_vma")` + `bpf_iter__task_vma` 上下文
- 读取 `vm_area_struct` 的 `vm_start`/`vm_end`/`vm_flags`
- 参数化过滤（`linfo.task.pid`）
- 对比 `/proc/<pid>/maps`：BPF iterator 可自定义输出格式和过滤条件
