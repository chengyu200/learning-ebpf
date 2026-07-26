# libbpf API 归类分析

> 来源：<https://libbpf.readthedocs.io/en/latest/api.html>
>
> 基于官方文档对 libbpf 全部 API 按功能维度进行系统归类，共统计 **351 个 `LIBBPF_API` 函数** 及大量宏，划分为 **47 个逻辑类别**。

---

## 一、文档顶层结构（按头文件）

| 头文件 | 内容定位 | 函数数 |
|---|---|---|
| `libbpf.h` | 高层 BPF 对象/程序/地图/链接 API（最大块） | 215 |
| `bpf.h` | 底层 `bpf()` 系统调用封装 | 58 |
| `btf.h` | BTF 类型信息 API | 78 |
| `xsk.h` | AF_XDP（文档渲染缺失，未含内容） | 0 |
| `bpf_tracing.h` | Tracing 寄存器/程序定义宏 | 全为宏 |
| `bpf_core_read.h` | CO-RE 读取/重定位宏 | 1 + 大量宏 |
| `bpf_endian.h` | 字节序转换宏 | 全为宏 |

每个头文件内部使用 `Functions` / `Defines` / `Enums` 子标题分组，无更细的 `###` 子分类，函数归类主要依赖命名前缀（`bpf_object__*`、`bpf_program__*`、`bpf_map__*`、`btf__*` 等）。

---

## 二、详细分类

### A. libbpf.h（高层 API，共 20 类）

#### 1. 版本与错误处理工具

| 函数 | 作用 |
|---|---|
| `libbpf_major_version` | 返回 libbpf 主版本号 |
| `libbpf_minor_version` | 返回 libbpf 次版本号 |
| `libbpf_version_string` | 返回人类可读版本字符串（如 "v1.7"） |
| `libbpf_strerror` | 将错误码转换为可读字符串 |
| `libbpf_bpf_attach_type_str` | attach type 枚举转字符串 |
| `libbpf_bpf_link_type_str` | link type 枚举转字符串 |
| `libbpf_bpf_map_type_str` | map type 枚举转字符串 |
| `libbpf_bpf_prog_type_str` | prog type 枚举转字符串 |

相关枚举：`libbpf_errno`（LIBBPF_ERRNO__* 起始值 4000）。

#### 2. 日志/调试

| 函数 | 作用 |
|---|---|
| `libbpf_set_print` | 注册用户日志回调（默认输出到 stderr） |

相关枚举：`libbpf_print_level`（WARN/INFO/DEBUG）。可由环境变量 `LIBBPF_LOG_LEVEL` 控制。

#### 3. BPF Object 生命周期（open/prepare/load/close）

| 函数 | 作用 |
|---|---|
| `bpf_object__open` | 从文件路径打开 ELF 并载入内存 |
| `bpf_object__open_file` | 同上，带 opts |
| `bpf_object__open_mem` | 从内存缓冲读取 ELF |
| `bpf_object__prepare` | ELF 处理/重定位/准备最终指令 |
| `bpf_object__load` | 加载到内核 |
| `bpf_object__close` | 关闭并释放所有资源 |

#### 4. BPF Object 持久化与访问器

| 函数 | 作用 |
|---|---|
| `bpf_object__pin_maps` / `__unpin_maps` | pin/unpin 全部 map |
| `bpf_object__pin_programs` / `__unpin_programs` | pin/unpin 全部程序 |
| `bpf_object__pin` / `__unpin` | pin/unpin 整个 object |
| `bpf_object__name` | 获取 object 名 |
| `bpf_object__kversion` / `__set_kversion` | 获取/设置内核版本 |
| `bpf_object__token_fd` | 关联的 BPF token FD |
| `bpf_object__btf` / `__btf_fd` | 关联 BTF 与其 FD |
| `bpf_object__find_program_by_name` | 按名查找程序 |
| `bpf_object__next_program` / `__prev_program` | 遍历程序 |
| `bpf_object__find_map_by_name` / `__find_map_fd_by_name` | 按名查找 map |
| `bpf_object__next_map` / `__prev_map` | 遍历 map |

相关宏：`bpf_object__for_each_program`、`bpf_object__for_each_map` / `bpf_map__for_each`。

#### 5. Section/类型名查找

| 函数 | 作用 |
|---|---|
| `libbpf_prog_type_by_name` | SEC() 名 → prog_type |
| `libbpf_attach_type_by_name` | SEC() 名 → attach_type |
| `libbpf_find_vmlinux_btf_id` | 按 attach type 解析 vmlinux BTF ID |

#### 6. BPF Program 操作

| 函数 | 作用 |
|---|---|
| `bpf_program__set_ifindex` | 设置 ifindex |
| `bpf_program__name` / `__section_name` | 名称/section 名 |
| `bpf_program__autoload` / `__set_autoload` | 是否自动加载 |
| `bpf_program__autoattach` / `__set_autoattach` | 是否自动 attach |
| `bpf_program__insns` / `__set_insns` / `__insn_cnt` | 指令数组 get/set/计数 |
| `bpf_program__fd` | 获取程序 FD |
| `bpf_program__pin` / `__unpin` | pin/unpin 程序 |
| `bpf_program__unload` | 卸载程序 |
| `bpf_program__type` / `__set_type` | 程序类型 get/set |
| `bpf_program__expected_attach_type` / `__set_expected_attach_type` | attach type get/set |
| `bpf_program__flags` / `__set_flags` | 标志 get/set |
| `bpf_program__log_level` / `__set_log_level` | 日志级别 get/set |
| `bpf_program__log_buf` / `__set_log_buf` | 日志缓冲 get/set |
| `bpf_program__func_info` / `__func_info_cnt` | 函数信息 |
| `bpf_program__line_info` / `__line_info_cnt` | 行信息 |
| `bpf_program__set_attach_target` | 设置 BTF 挂载目标 |
| `bpf_program__assoc_struct_ops` | 关联 struct_ops map |
| `bpf_program__clone` | 克隆加载单个程序 |

#### 7. BPF Link 操作

| 函数 | 作用 |
|---|---|
| `bpf_link__open` | 从 BPFFS 路径打开 link |
| `bpf_link__fd` | 获取 link FD |
| `bpf_link__pin_path` | 获取 pin 路径 |
| `bpf_link__pin` / `__unpin` | pin/unpin link |
| `bpf_link__update_program` | 更新关联程序 |
| `bpf_link__update_map` | 更新关联 map |
| `bpf_link__disconnect` | 断开 userspace 句柄 |
| `bpf_link__detach` | 分离 link |
| `bpf_link__destroy` | 销毁 link |

#### 8. 程序 Attach（所有挂钩点类型，最庞大的一类）

**通用：**
- `bpf_program__attach` — 自动检测类型并 attach

**perf_event：**
- `bpf_program__attach_perf_event` / `__attach_perf_event_opts`

**kprobe 系列：**
- `bpf_program__attach_kprobe` / `__attach_kprobe_opts`
- `bpf_program__attach_kprobe_multi_opts` — 多 kprobe
- `bpf_program__attach_ksyscall` — syscall kprobe

**uprobe 系列：**
- `bpf_program__attach_uprobe` / `__attach_uprobe_opts`
- `bpf_program__attach_uprobe_multi` — 多 uprobe

**tracepoint 系列：**
- `bpf_program__attach_tracepoint` / `__attach_tracepoint_opts`
- `bpf_program__attach_raw_tracepoint` / `__attach_raw_tracepoint_opts`

**tracing 系列：**
- `bpf_program__attach_trace` / `__attach_trace_opts`
- `bpf_program__attach_tracing_multi`

**LSM/cgroup/netns/sockmap/xdp：**
- `bpf_program__attach_lsm`
- `bpf_program__attach_cgroup` / `__attach_cgroup_opts`
- `bpf_program__attach_netns`
- `bpf_program__attach_sockmap`
- `bpf_program__attach_xdp`

**freplace/netfilter/tcx/netkit/iter：**
- `bpf_program__attach_freplace`
- `bpf_program__attach_netfilter`
- `bpf_program__attach_tcx`
- `bpf_program__attach_netkit`
- `bpf_program__attach_iter`

**USDT：**
- `bpf_program__attach_usdt`

**struct_ops：**
- `bpf_map__attach_struct_ops`

相关枚举：`probe_attach_mode`（DEFAULT/LEGACY/PERF/LINK）。

#### 9. BPF Map 操作

**属性 get/set：**
- `bpf_map__type` / `__set_type`
- `bpf_map__max_entries` / `__set_max_entries`
- `bpf_map__key_size` / `__set_key_size`
- `bpf_map__value_size` / `__set_value_size`
- `bpf_map__map_flags` / `__set_map_flags`
- `bpf_map__numa_node` / `__set_numa_node`
- `bpf_map__btf_key_type_id` / `__btf_value_type_id`
- `bpf_map__ifindex` / `__set_ifindex`
- `bpf_map__map_extra` / `__set_map_extra`

**autocreate/autoattach：**
- `bpf_map__set_autocreate` / `__autocreate`
- `bpf_map__set_autoattach` / `__autoattach`

**FD 与复用：**
- `bpf_map__fd` / `bpf_map__reuse_fd`
- `bpf_map__name`

**pin：**
- `bpf_map__pin` / `__unpin` / `__set_pin_path` / `__pin_path` / `__is_pinned`

**嵌套 map：**
- `bpf_map__set_inner_map_fd` / `__inner_map`

**初始值：**
- `bpf_map__set_initial_value` / `__initial_value` / `__is_internal`

**元素操作（高层带尺寸校验）：**
- `bpf_map__lookup_elem`
- `bpf_map__update_elem`
- `bpf_map__delete_elem`
- `bpf_map__lookup_and_delete_elem`
- `bpf_map__get_next_key`

**排他性：**
- `bpf_map__set_exclusive_program` / `__exclusive_program`

#### 10. XDP 网络

| 函数 | 作用 |
|---|---|
| `bpf_xdp_attach` | attach XDP 程序到网卡 |
| `bpf_xdp_detach` | detach XDP 程序 |
| `bpf_xdp_query` | 查询 XDP 状态（带 opts） |
| `bpf_xdp_query_id` | 查询 XDP prog ID |

#### 11. TC（流量控制）网络

| 函数 | 作用 |
|---|---|
| `bpf_tc_hook_create` | 创建 clsact qdisc hook |
| `bpf_tc_hook_destroy` | 销毁 hook |
| `bpf_tc_attach` | attach 程序到 ingress/egress |
| `bpf_tc_detach` | detach 程序 |
| `bpf_tc_query` | 查询已挂载程序 |

相关枚举：`bpf_tc_attach_point`（INGRESS/EGRESS/CUSTOM/QDISC）、`bpf_tc_flags`（F_REPLACE）。相关宏：`BPF_TC_PARENT`。

#### 12. Ring Buffer（BPF → 用户态）

**管理器 API：**
- `ring_buffer__new` / `__free` — 创建/释放管理器
- `ring_buffer__add` — 添加 ringbuf map FD
- `ring_buffer__poll` / `__consume` / `__consume_n` — 轮询/消费
- `ring_buffer__epoll_fd` — 获取 epoll FD
- `ring_buffer__ring` — 取第 idx 个 ring 对象

**单环 API：**
- `ring__consumer_pos` / `__producer_pos` — 消费者/生产者位置
- `ring__avail_data_size` / `__size` — 可用数据/总大小
- `ring__map_fd` — 底层 map FD
- `ring__consume` / `__consume_n` — 单环消费

#### 13. User Ring Buffer（用户态 → BPF）

| 函数 | 作用 |
|---|---|
| `user_ring_buffer__new` | 创建用户 ring buffer |
| `user_ring_buffer__reserve` | 预留样本空间 |
| `user_ring_buffer__reserve_blocking` | 阻塞式预留（带 timeout） |
| `user_ring_buffer__submit` | 提交样本到内核 |
| `user_ring_buffer__discard` | 丢弃预留样本 |
| `user_ring_buffer__free` | 释放 |

#### 14. Perf Buffer

| 函数 | 作用 |
|---|---|
| `perf_buffer__new` / `__new_raw` | 创建 perf buffer |
| `perf_buffer__free` | 释放 |
| `perf_buffer__epoll_fd` | 获取 epoll FD |
| `perf_buffer__poll` / `__consume` / `__consume_buffer` | 轮询/消费 |
| `perf_buffer__buffer_cnt` | 缓冲区数量 |
| `perf_buffer__buffer_fd` / `__buffer` | 底层 FD 与缓冲区对象 |

相关枚举：`bpf_perf_event_ret`（DONE/ERROR/CONT）。

#### 15. 程序行信息（bpf_prog_linfo）

| 函数 | 作用 |
|---|---|
| `bpf_prog_linfo__new` / `__free` | 从 bpf_prog_info 构造/释放 |
| `bpf_prog_linfo__lfind_addr_func` | 按地址查找 |
| `bpf_prog_linfo__lfind` | 按指令偏移查找 |

#### 16. 特性探测

| 函数 | 作用 |
|---|---|
| `libbpf_probe_bpf_prog_type` | 探测内核是否支持某 prog 类型 |
| `libbpf_probe_bpf_map_type` | 探测是否支持某 map 类型 |
| `libbpf_probe_bpf_helper` | 探测是否支持某 helper 函数 |

#### 17. CPU/NUMA 工具

| 函数 | 作用 |
|---|---|
| `libbpf_num_possible_cpus` | 返回系统可能 CPU 数（per-CPU map 必需） |

#### 18. Skeleton 相关

| 函数 | 作用 |
|---|---|
| `bpf_object__open_skeleton` | 打开 skeleton |
| `bpf_object__load_skeleton` | 加载 skeleton |
| `bpf_object__attach_skeleton` | attach skeleton |
| `bpf_object__detach_skeleton` | detach skeleton |
| `bpf_object__destroy_skeleton` | 销毁 skeleton |
| `bpf_object__open_subskeleton` | 打开子 skeleton |
| `bpf_object__destroy_subskeleton` | 销毁子 skeleton |
| `bpf_object__gen_loader` | 生成 light-skeleton loader |

#### 19. BPF 链接器

| 函数 | 作用 |
|---|---|
| `bpf_linker__new` / `__new_fd` | 创建链接器（输出到文件/FD） |
| `bpf_linker__add_file` / `__add_fd` / `__add_buf` | 添加输入 ELF |
| `bpf_linker__finalize` | 完成链接 |
| `bpf_linker__free` | 释放 |

#### 20. 自定义 SEC() 处理器

| 函数 | 作用 |
|---|---|
| `libbpf_register_prog_handler` | 注册自定义 SEC() handler |
| `libbpf_unregister_prog_handler` | 注销 |

---

### B. bpf.h（系统调用封装，共 12 类）

> 特点：基于裸 FD，是 `libbpf.h` 高层 API 的底层对应物。`bpf_map__*`（高层）对应 `bpf_map_*`（底层），前者带尺寸校验更安全。

#### 21. Memlock 限制

| 函数 | 作用 |
|---|---|
| `libbpf_set_memlock_rlim` | 设置 RLIMIT_MEMLOCK（旧内核必需） |

#### 22. 对象创建与加载

| 函数 | 作用 |
|---|---|
| `bpf_map_create` | 创建 map（返回 FD） |
| `bpf_prog_load` | 加载程序（返回 FD） |
| `bpf_btf_load` | 加载 BTF（返回 FD） |

#### 23. Map 元素操作（FD 级）

| 函数 | 作用 |
|---|---|
| `bpf_map_update_elem` | 插入/更新元素 |
| `bpf_map_lookup_elem` / `__lookup_elem_flags` | 查找元素 |
| `bpf_map_lookup_and_delete_elem` / `__lookup_and_delete_elem_flags` | 查找并原子删除 |
| `bpf_map_delete_elem` / `__delete_elem_flags` | 删除元素 |
| `bpf_map_get_next_key` | 遍历 key |
| `bpf_map_freeze` | 冻结 map 为只读 |

#### 24. Map 批量操作

| 函数 | 作用 |
|---|---|
| `bpf_map_delete_batch` | 批量删除 |
| `bpf_map_lookup_batch` | 批量查找 |
| `bpf_map_lookup_and_delete_batch` | 批量查找并删除 |
| `bpf_map_update_batch` | 批量更新 |

#### 25. 对象 Pin/Get

| 函数 | 作用 |
|---|---|
| `bpf_obj_pin` / `bpf_obj_pin_opts` | pin FD 到 BPFFS 路径 |
| `bpf_obj_get` / `bpf_obj_get_opts` | 从路径获取已 pin 对象的 FD |

#### 26. 程序 Attach/Detach（FD 级）

| 函数 | 作用 |
|---|---|
| `bpf_prog_attach` / `bpf_prog_attach_opts` | attach 程序到目标 |
| `bpf_prog_detach` / `bpf_prog_detach2` / `bpf_prog_detach_opts` | detach 程序 |

#### 27. Link 创建/Detach/Update/Iter

| 函数 | 作用 |
|---|---|
| `bpf_link_create` | 创建 link |
| `bpf_link_detach` | detach link |
| `bpf_link_update` | 用新程序更新 link |
| `bpf_iter_create` | 从 link 创建 iter FD |

#### 28. ID 枚举与按 ID 取 FD

| 函数 | 作用 |
|---|---|
| `bpf_prog_get_next_id` / `bpf_map_get_next_id` / `bpf_btf_get_next_id` / `bpf_link_get_next_id` | 枚举内核中各类对象 ID |
| `bpf_prog_get_fd_by_id` / `__get_fd_by_id_opts` | 按 ID 取 prog FD |
| `bpf_map_get_fd_by_id` / `__get_fd_by_id_opts` | 按 ID 取 map FD |
| `bpf_btf_get_fd_by_id` / `__get_fd_by_id_opts` | 按 ID 取 btf FD |
| `bpf_link_get_fd_by_id` / `__get_fd_by_id_opts` | 按 ID 取 link FD |

#### 29. 按 FD 取 Info

| 函数 | 作用 |
|---|---|
| `bpf_obj_get_info_by_fd` | 通用对象 info |
| `bpf_prog_get_info_by_fd` | 程序 info |
| `bpf_map_get_info_by_fd` | map info |
| `bpf_btf_get_info_by_fd` | btf info |
| `bpf_link_get_info_by_fd` | link info |

#### 30. 程序查询

| 函数 | 作用 |
|---|---|
| `bpf_prog_query_opts` / `bpf_prog_query` | 查询目标上已挂载的程序/链接 |

#### 31. Raw Tracepoint 与 Task FD

| 函数 | 作用 |
|---|---|
| `bpf_raw_tracepoint_open_opts` | 带 opts 打开 raw tracepoint |
| `bpf_raw_tracepoint_open` | 按名打开 raw tracepoint |
| `bpf_task_fd_query` | 查询 pid FD 对应的 BPF 程序 |

#### 32. 统计/绑定/测试运行/Token/Stream/Struct Ops

| 函数 | 作用 |
|---|---|
| `bpf_enable_stats` | 启用 BPF 统计 |
| `bpf_prog_bind_map` | 绑定 map 到程序 |
| `bpf_prog_test_run_opts` | 测试运行程序 |
| `bpf_token_create` | 创建 BPF token（委派） |
| `bpf_prog_stream_read` | 读取程序 stream |
| `bpf_prog_assoc_struct_ops` | FD 级关联 struct_ops |

---

### C. btf.h（BTF API，共 8 类）

#### 33. BTF 生命周期

| 函数 | 作用 |
|---|---|
| `btf__free` | 释放 |
| `btf__new` / `__new_split` | 从 raw 数据构造（split 变体） |
| `btf__new_empty` / `__new_empty_split` / `__new_empty_opts` | 创建空 BTF |
| `btf__distill_base` | 蒸馏 base BTF |
| `btf__parse` / `__parse_split` / `__parse_elf` / `__parse_elf_split` / `__parse_raw` / `__parse_raw_split` | 多种格式解析 |
| `btf__load_vmlinux_btf` | 加载 vmlinux BTF |
| `btf__load_module_btf` | 加载模块 BTF |
| `btf__load_from_kernel_by_id` / `__load_from_kernel_by_id_split` | 按 ID 从内核加载 |
| `btf__load_into_kernel` | 加载 BTF 到内核 |

#### 34. BTF 访问与查询

| 函数 | 作用 |
|---|---|
| `btf__find_by_name` / `__find_by_name_kind` | 按名/名+kind 查找类型 |
| `btf__type_cnt` | 类型总数 |
| `btf__base_btf` | 获取 base BTF |
| `btf__type_by_id` | 按 ID 取类型 |
| `btf__pointer_size` / `__set_pointer_size` | 指针大小 get/set |
| `btf__endianness` / `__set_endianness` | 字节序 get/set |
| `btf__resolve_size` / `__resolve_type` | 解析大小/类型 |
| `btf__align_of` | 类型对齐 |
| `btf__fd` / `__set_fd` | FD get/set |
| `btf__raw_data` | 原始数据 |
| `btf__name_by_offset` / `__str_by_offset` | 按偏移取字符串 |

相关枚举：`btf_endianness`（LITTLE/BIG_ENDIAN）。

#### 35. BTF Ext（扩展数据）

| 函数 | 作用 |
|---|---|
| `btf_ext__new` / `__free` | 解析/释放 BTF.ext |
| `btf_ext__raw_data` | 原始数据 |
| `btf_ext__endianness` / `__set_endianness` | 字节序 get/set |

#### 36. BTF 字符串与类型操作

| 函数 | 作用 |
|---|---|
| `btf__find_str` | 查找字符串 |
| `btf__add_str` | 添加字符串 |
| `btf__add_type` | 从其他 BTF 复制单类型 |
| `btf__add_btf` | 从其他 BTF 批量复制 |

#### 37. BTF 类型构造（`btf__add_*` 全套）

| 函数 | 作用 |
|---|---|
| `btf__add_int` / `__add_float` | 基础类型 |
| `btf__add_ptr` / `__add_array` | 指针/数组 |
| `btf__add_struct` / `__add_union` / `__add_field` | struct/union 及字段 |
| `btf__add_enum` / `__add_enum_value` | enum + 值 |
| `btf__add_enum64` / `__add_enum64_value` | enum64 + 值 |
| `btf__add_fwd` | 前向声明 |
| `btf__add_typedef` / `__add_volatile` / `__add_const` / `__add_restrict` | 修饰符 |
| `btf__add_type_tag` / `__add_type_attr` | 类型标签 |
| `btf__add_func` / `__add_func_proto` / `__add_func_param` | 函数 + 原型 + 参数 |
| `btf__add_var` / `__add_datasec` / `__add_datasec_var_info` | 变量/数据段 |
| `btf__add_decl_tag` / `__add_decl_attr` | 声明标签 |

相关枚举：`btf_fwd_kind`（STRUCT/UNION/ENUM）。相关宏：`BTF_KIND_*` 常量。

#### 38. BTF 去重/重定位/置换

| 函数 | 作用 |
|---|---|
| `btf__dedup` | 去重类型 |
| `btf__relocate` | 对新 base 重定位 split BTF |
| `btf__permute` | 原地置换类型 ID 顺序 |

#### 39. BTF Dump

| 函数 | 作用 |
|---|---|
| `btf_dump__new` / `__free` | 创建/释放 dumper |
| `btf_dump__dump_type` | pretty-print 类型 |
| `btf_dump__emit_type_decl` | 输出 C 风格类型声明 |
| `btf_dump__dump_type_data` | dump 类型化数据值 |

#### 40. BTF 类型 inline 访问器（static inline）

| 函数 | 作用 |
|---|---|
| `btf_kind` / `btf_vlen` / `btf_kflag` | 类型 kind/变长数/kflag |
| `btf_is_void/int/ptr/array/struct/union/composite/enum/enum64/fwd/typedef/volatile/const/restrict/mod/func/func_proto/var/datasec/float/decl_tag/type_tag/any_enum` | 类型判定 |
| `btf_int_encoding/offset/bits` | int 详情 |
| `btf_array` / `btf_enum` / `btf_enum64` / `btf_enum64_value` | 取复合结构 |
| `btf_members` / `btf_member_bit_offset` / `btf_member_bitfield_size` | struct/union 成员 |
| `btf_params` / `btf_var` / `btf_var_secinfos` / `btf_decl_tag` | 其他子结构 |
| `btf_kind_core_compat` | CO-RE kind 兼容性 |

---

### D. bpf_tracing.h（Tracing 宏，共 2 类）

#### 41. PT_REGS 寄存器访问宏

- 通用：`PT_REGS_PARM1..8`、`PT_REGS_RET`、`PT_REGS_FP`、`PT_REGS_RC`、`PT_REGS_SP`、`PT_REGS_IP`
- CO-RE 变体：`PT_REGS_PARM1_CORE..8_CORE`、`PT_REGS_RET_CORE`、`PT_REGS_FP_CORE`、`PT_REGS_RC_CORE`、`PT_REGS_SP_CORE`、`PT_REGS_IP_CORE`
- Syscall 变体：`PT_REGS_PARM1_SYSCALL..7_SYSCALL`、`PT_REGS_PARM1_CORE_SYSCALL..7_CORE_SYSCALL`
- 其他：`PT_REGS_SYSCALL_REGS`、`BPF_KPROBE_READ_RET_IP`、`BPF_KRETPROBE_READ_RET_IP`

相关宏：`__BPF_TARGET_MISSING`（未设置目标架构时触发错误）。

#### 42. Tracing 程序定义宏

| 宏 | 作用 |
|---|---|
| `BPF_PROG` / `BPF_PROG2` | 通用 tracing handler 定义 |
| `BPF_KPROBE` / `BPF_KRETPROBE` | kprobe/kretprobe handler |
| `BPF_KSYSCALL` / `BPF_KPROBE_SYSCALL` | syscall kprobe handler |
| `BPF_UPROBE` / `BPF_URETPROBE` | uprobe/uretprobe handler |

特点：自动从 `pt_regs` 提取命名参数，提供类型安全的函数签名。

---

### E. bpf_core_read.h（CO-RE 宏，共 3 类）

#### 43. CO-RE 字段/类型/枚举重定位

| 宏/函数 | 作用 |
|---|---|
| `bpf_core_field_exists` / `bpf_core_field_size` / `bpf_core_field_offset` | 字段存在性/大小/偏移 |
| `bpf_core_type_id_local` / `bpf_core_type_id_kernel` | 类型 ID（本地/内核） |
| `bpf_core_type_exists` / `bpf_core_type_matches` / `bpf_core_type_size` | 类型存在性/匹配/大小 |
| `bpf_core_enum_value_exists` / `bpf_core_enum_value` | 枚举值存在性/取值 |
| `bpf_core_cast` | CO-RE 类型转换 |
| `bpf_rdonly_cast`（函数） | 只读 ksym 类型转换 |

相关枚举：`bpf_field_info_kind`、`bpf_type_id_kind`、`bpf_type_info_kind`、`bpf_enum_value_kind`。

#### 44. CO-RE 内存读取宏

| 宏 | 作用 |
|---|---|
| `bpf_core_read` / `bpf_core_read_user` / `bpf_core_read_str` / `bpf_core_read_user_str` | 直接读取 |
| `BPF_CORE_READ_INTO` / `BPF_CORE_READ_USER_INTO` | 读入指定缓冲 |
| `BPF_PROBE_READ_INTO` / `BPF_PROBE_READ_USER_INTO` | probe read 读入 |
| `BPF_CORE_READ_STR_INTO` / `BPF_CORE_READ_USER_STR_INTO` | 字符串读入 |
| `BPF_PROBE_READ_STR_INTO` / `BPF_PROBE_READ_USER_STR_INTO` | probe read 字符串读入 |
| `BPF_CORE_READ` / `BPF_CORE_READ_USER` | 链式解引用 |
| `BPF_PROBE_READ` / `BPF_PROBE_READ_USER` | 非链式 probe read |

特点：沿 BTF 访问索引链式解引用，编译期重定位，运行时零开销。

#### 45. CO-RE 位域宏

| 宏 | 作用 |
|---|---|
| `__CORE_RELO` | 内部重定位原语 |
| `__CORE_BITFIELD_PROBE_READ` | 内部位域 probe read |
| `BPF_CORE_READ_BITFIELD_PROBED` | probe read 位域读取 |
| `BPF_CORE_READ_BITFIELD` | 直接位域读取 |
| `BPF_CORE_WRITE_BITFIELD` | 位域写入 |

---

### F. bpf_endian.h（1 类）

#### 46. 字节序转换

| 宏 | 作用 |
|---|---|
| `bpf_htons` / `bpf_ntohs` | 16 位 host ↔ network |
| `bpf_htonl` / `bpf_ntohl` | 32 位 host ↔ network |
| `bpf_cpu_to_be64` / `bpf_be64_to_cpu` | 64 位 host ↔ big-endian |

特点：编译期常量优化，内部使用 `__bpf_*` 与 `__bpf_constant_*` 辅助宏。

---

### G. xsk.h（缺失）

#### 47. AF_XDP 套接字

文档生成器无法找到 `xsk.h`，此节为空。预期覆盖 AF_XDP（XSK）套接字 setup 与 umem/cursor API。

---

## 三、关键观察与总结

### 1. 分层清晰

- `libbpf.h` 是**高层抽象**，基于对象句柄（`bpf_object*`/`bpf_program*`/`bpf_map*`/`bpf_link*`）
- `bpf.h` 是**底层系统调用封装**，基于裸 FD
- 两者一一对应，但高层版本带尺寸校验更安全（如 `bpf_map__lookup_elem` vs `bpf_map_lookup_elem`）

### 2. Attach 类型最丰富

第 8 类涵盖 25+ 种 attach 变体，是 API 中最庞大的部分，反映 BPF 挂钩点（hook）的多样性。覆盖：

- 内核探针：kprobe/kretprobe/kprobe_multi/ksyscall
- 用户探针：uprobe/uretprobe/uprobe_multi
- 静态追踪：tracepoint/raw_tracepoint/USDT
- 函数追踪：tracing/fentry/fexit/fmod_ret
- 安全：LSM
- 网络：cgroup/netns/sockmap/xdp/tcx/netkit/netfilter
- 扩展：freplace
- 迭代器：iter
- 结构操作：struct_ops

### 3. BTF 是独立子系统

含 78 个函数，覆盖从**构造 → 去重 → Dump → 重定位**的全流程，可脱离 BPF 程序独立使用（如类型反射、调试器）。

### 4. CO-RE 与 Tracing 以宏为主

`bpf_tracing.h` 与 `bpf_core_read.h` 几乎全是宏，编译期重定位、运行时零开销，体现 eBPF 的可移植性核心。

### 5. Skeleton 是推荐用法

现代 libbpf 程序通过 `bpftool gen skeleton` 生成代码，调用第 18 类 API 简化生命周期管理，避免手动管理 FD 与 map 指针。

### 6. 各类 API 数量分布

| 区块 | 类别数 | 备注 |
|---|---|---|
| libbpf.h | 20 | 高层 API 主力 |
| bpf.h | 12 | 系统调用封装 |
| btf.h | 8 | BTF 子系统 |
| bpf_tracing.h | 2 | 全为宏 |
| bpf_core_read.h | 3 | CO-RE 宏 |
| bpf_endian.h | 1 | 字节序 |
| **合计** | **47** | |

### 7. 相关枚举汇总

- libbpf.h：`libbpf_errno`、`libbpf_print_level`、`probe_attach_mode`、`bpf_tc_attach_point`、`bpf_tc_flags`、`bpf_perf_event_ret`、`libbpf_tristate`
- btf.h：`btf_endianness`、`btf_fwd_kind`
- bpf_core_read.h：`bpf_field_info_kind`、`bpf_type_id_kind`、`bpf_type_info_kind`、`bpf_enum_value_kind`
