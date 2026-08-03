# 60-iter-bpf-map — BPF Map 内容导出器

## 概述

用 `SEC("iter/bpf_map")` 遍历系统中所有 BPF map，输出 id/type/key_size/value_size/max_entries/name。类似 `bpftool map show`，但用 BPF iterator 实现。

## 编译与运行

```bash
make -C src/60-iter-bpf-map
sudo ./src/60-iter-bpf-map/iter-bpf-map
```

## 输出示例

```bash
# ./iter-bpf-map 
=== All BPF Maps ===
id       type       key_sz     value_sz     max_entries  name
45       2          4          124          1            .rodata
2260     13         8          4            2048         cgroup_hash
2262     8          4          4            1            cgroup_map
2263     27         0          0            262144       written_sysctls
2265     2          4          5            1            .rodata.str1.1
2706     2          4          32           1            libbpf_global
2707     2          4          66           1            iter_bpf.rodata
2708     2          4          41           1            .rodata.str1.1
2709     2          4          32           1            libbpf_det_bind
```

## 教学概念

- `SEC("iter/bpf_map")` + `bpf_iter__bpf_map` 上下文
- `BPF_CORE_READ` 读取 `bpf_map` 结构体字段
- 遍历系统全局 BPF map（不限于本程序的 map）
- 对比 `bpftool map show`：BPF iterator 可自定义输出格式
