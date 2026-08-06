# 70-fexit-unlink — 用 fexit 追踪文件删除结果

## 概述

用两个 `fexit` 程序配合追踪文件删除操作的**完整结果**（成功/失败/文件不存在）：

1. **`fexit/vfs_unlink`** — VFS 层退出，能读取文件名，捕获权限失败等
2. **`fexit/__arm64_sys_unlinkat`** — 系统调用退出，捕获所有结果（含 ENOENT）

### 为什么需要两个程序？

```
rm /nonexistent 的内核调用链：

__arm64_sys_unlinkat()          ← fexit ② 在此捕获 ret=-ENOENT
  └─ do_unlinkat()（被内联）
       ├─ filename_lookup()     ← 路径查找失败 (ENOENT)
       ├─ 直接返回 -ENOENT      ← 不会继续往下走
       └─ vfs_unlink()          ← 永远不会到达！

rm /tmp/existing 的内核调用链：

__arm64_sys_unlinkat()          ← fexit ② 在此捕获 ret=0（跳过，避免重复）
  └─ do_unlinkat()（被内联）
       ├─ filename_lookup()     ← 路径查找成功
       └─ vfs_unlink()          ← fexit ① 在此捕获 ret + 文件名
            └─ 返回 0 (成功) 或负数 (权限等错误)
```

| 场景 | vfs_unlink | __arm64_sys_unlinkat |
|---|---|---|
| 删除存在的文件 | ✅ 有文件名 + ret | ✅ ret=0（跳过避免重复） |
| 文件不存在 (ENOENT) | ❌ 不触发 | ✅ ret=-ENOENT |
| 权限不足 (EPERM) | ✅ 有文件名 + ret | ✅ ret=-EPERM（跳过避免重复） |
| 只读文件系统 (EROFS) | ✅ 有文件名 + ret | ✅ ret=-EROFS（跳过避免重复） |

### fexit vs fentry

| 特性 | fentry（示例 3） | fexit（本示例） |
|---|---|---|
| 触发时机 | 函数入口 | 函数出口 |
| 输入参数 | ✅ | ✅ |
| **返回值** | ❌ | ✅（BPF_PROG 最后一个参数） |
| 知道删除结果？ | ❌ 不知道 | ✅ **成功/失败 + 错误码** |

### BPF_PROG 宏：fexit 的返回值

fexit 的 `BPF_PROG` 参数 = 原始函数参数 **+ ret**（返回值，最后一个参数）：

```c
/* vfs_unlink 签名：
 *   int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir,
 *                  struct dentry *dentry, struct inode **delegated);
 */

/* fentry: 只有输入参数 */
SEC("fentry/vfs_unlink")
int BPF_PROG(handler, idmap, dir, dentry, delegated) { ... }

/* fexit: 输入参数 + 返回值 */
SEC("fexit/vfs_unlink")
int BPF_PROG(handler, idmap, dir, dentry, delegated, int ret) {
    /* ret = 0 表示成功，负数表示错误码 */
}
```

## 编译与运行

```bash
make -C src/70-fexit-unlink
sudo ./src/70-fexit-unlink/fexit-unlink

# 另开终端测试
rm /tmp/test_file          # SUCCESS (0)  文件名来自 vfs_unlink
rm /nonexistent            # FAILED (-2 ENOENT)  来自 __arm64_sys_unlinkat
rm /proc/1/mem             # FAILED (-1 EPERM)  文件名来自 vfs_unlink
```

### 注意：do_unlinkat 被内联

`do_unlinkat` 在内核中被编译器内联到 `__arm64_sys_unlinkat` 中，无法直接用 `fexit/do_unlinkat` 挂载。因此用 `fexit/__arm64_sys_unlinkat` 替代。

## 输出示例

```
Tracing unlink results (fexit). Ctrl-C to stop.
Test: rm /tmp/test (success) | rm /nonexistent (ENOENT) | rm /proc/1/mem (EPERM)

[SUCCESS] pid=1234   uid=0     comm=rm           file=test_file
[FAILED]  pid=1235   uid=0     comm=rm           file=mem                      errno=1 (Operation not permitted)
[FAILED]  pid=1236   uid=0     comm=rm           file=(unknown)                errno=2 (No such file or directory)

=== Summary ===
  Success: 1
  Failed:  2
  Total:   3
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `SEC("fexit/...")` | 在内核函数退出时触发 |
| `BPF_TRACE_FEXIT` | attach type，通过 BTF ID 解析 |
| `BPF_PROG(..., int ret)` | fexit 的返回值作为最后一个参数 |
| 返回值含义 | `ret=0` 成功，`ret<0` 失败（`-ret` 为 errno） |
| `BPF_CORE_READ` | CO-RE 读取 `dentry->d_name.name` |

## 与系列示例的关系

| 示例 | 类型 | 挂载点 | 返回值 | 延迟测量 | 教学递进 |
|---|---|---|---|---|---|
| 2-kprobe-unlink | kprobe | vfs_unlink | ❌ | ❌ | 基础：kprobe |
| 3-fentry-unlink | fentry | vfs_unlink | ❌ | ❌ | 进阶：fentry（类型安全） |
| **70-fexit-unlink** | **fexit** | **vfs_unlink** | **✅** | ❌ | **进阶：fexit（返回值）** |
| 64-fsession | fsession | vfs_read | ✅ | ✅ | 高级：fentry+fexit 合一 |

## 文件结构

```
70-fexit-unlink/
├── Makefile
├── README.md
├── fexit-unlink.h          # 共享事件结构体（含 ret 字段）
├── fexit-unlink.bpf.c      # fexit/vfs_unlink + BPF_PROG(..., int ret)
└── fexit-unlink.c          # 用户态：ringbuf 轮询 + 成功/失败统计
```
