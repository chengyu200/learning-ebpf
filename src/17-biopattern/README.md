# 17-biopattern

统计随机 vs 顺序磁盘 I/O。

## 做什么

- 内核态：挂 `tracepoint/block/block_rq_complete`，按设备号在哈希表中累加：若本次起始扇区 == 上次结束扇区则顺序 +1，否则随机 +1，并累加字节数。
- 用户态：周期性遍历哈希表打印每设备的统计，并在打印后重置计数。

## 教学概念

- 块设备 tracepoint、`BPF_CORE_READ` 读 tracepoint 结构体字段。
- `bpf_map_lookup_or_try_init`（见 `src/common/maps.bpf.h`）。
- 用户态遍历哈希表并周期重置。

## 运行

```bash
make -C src/17-biopattern
sudo ./src/17-biopattern/biopattern -i 3
# 另开终端产生 I/O，例如：
dd if=/dev/zero of=/tmp/bio_test bs=64k count=64 oflag=direct; rm -f /tmp/bio_test
```

## 适配说明

本机内核的 `block_rq_complete` tracepoint 对应 `trace_event_raw_block_rq`（已由本仓库从运行内核生成的 `vmlinux.h` 提供），故无需原教程的 `core_fixes.bpf.h` 兼容层。
