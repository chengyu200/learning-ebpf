# 15-javagc

通过 USDT（User Statically-Defined Tracepoints）捕获 Java GC 时长。

## 做什么

- 内核态：`SEC("usdt")` 程序挂钩 HotSpot 的 `gc__begin`/`gc__end` 与 `mem__pool_gc_begin`/`mem__pool_gc_end` 探针，配对 start/end，超过阈值的 GC 时长通过 perf event array 输出。
- 用户态：用 `bpf_program__attach_usdt` 把程序挂到目标 Java 进程的 libjvm.so 上。

## 教学概念

- USDT 程序、`bpf/usdt.bpf.h`、`bpf_program__attach_usdt`（provider/name/pid/binary_path）。
- 与 uprobe 的区别：USDT 是二进制中预留的稳定探测点。

## 运行（需要 JVM）

本机未安装 Java，此示例**仅保证编译通过**。运行需要：

1. 安装带 HotSpot USDT 支持的 JDK（OpenJDK HotSpot）。
2. 找到 libjvm.so 路径，例如：
   ```bash
   find /usr/lib/jvm -name libjvm.so
   ```
3. 启动一个 Java 进程并获取其 PID，然后：
   ```bash
   sudo ./src/15-javagc/javagc --pid <PID> --libjvm /path/to/libjvm.so
   ```
4. 触发 GC（例如用 `jcmd <PID> GC.run`）。
