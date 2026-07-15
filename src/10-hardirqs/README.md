# 10-hardirqs

统计硬中断耗时（按 IRQ 号）。

## 做什么

- 内核态：
  - `irq_handler_entry`：记录开始时间戳（哈希表，键为 `(cpu<<32)|irq`，避免跨 CPU 串扰）；
  - `irq_handler_exit`：计算耗时，累加到另一个哈希表（键为 irq，值为 `{total_ns, count}`）。
- 用户态：Ctrl-C 时用 `bpf_map__get_next_key` 遍历哈希表打印每个 IRQ 的计数与总耗时。

## 教学概念

- 中断 tracepoint `tp/irq/irq_handler_entry|exit`。
- per-cpu 哈希表（`bpf_get_smp_processor_id` 组合键）保存进行中的状态。
- 累加到按键聚合的哈希表；用户态遍历哈希表（`get_next_key` / `lookup_elem`）。

## 运行

```bash
make -C src/10-hardirqs
sudo ./src/10-hardirqs/hardirqs
# 运行几秒后按 Ctrl-C 打印统计
```
