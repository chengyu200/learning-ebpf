# 62-iter-cgroup — Cgroup 层级遍历

## 概述

用 `SEC("iter/cgroup")` 遍历 cgroup v2 层级树，输出每个 cgroup 的 id、level、子节点数、名称。支持多种遍历顺序和指定起始 cgroup。

### 遍历顺序

| `--order` | 枚举值 | 说明 |
|---|---|---|
| `self` | `BPF_CGROUP_ITER_SELF_ONLY` (1) | 仅遍历指定 cgroup 自身 |
| `pre` | `BPF_CGROUP_ITER_DESCENDANTS_PRE` (2) | 前序遍历所有后代（默认） |
| `post` | `BPF_CGROUP_ITER_DESCENDANTS_POST` (3) | 后序遍历所有后代 |
| `ancestors` | `BPF_CGROUP_ITER_ANCESTORS_UP` (4) | 从指定 cgroup 向上遍历祖先 |

### iter/cgroup 的 attach 要求

与 `iter/task` 不同，`iter/cgroup` **必须**通过 `bpf_iter_attach_opts` 指定：
- `linfo.cgroup.order`：遍历顺序
- `linfo.cgroup.cgroup_fd`：起始 cgroup 的 fd（通过 `open("/sys/fs/cgroup/...", O_RDONLY)` 获取）

不指定时 attach 会返回 `-EINVAL`。

## 编译与运行

```bash
make -C src/62-iter-cgroup

# 前序遍历根 cgroup 的所有后代（默认）
sudo ./src/62-iter-cgroup/iter-cgroup

# 仅遍历指定 cgroup 自身
sudo ./src/62-iter-cgroup/iter-cgroup --order self --cgroup /sys/fs/cgroup/system.slice

# 从指定 cgroup 向上遍历祖先
sudo ./src/62-iter-cgroup/iter-cgroup --order ancestors --cgroup /sys/fs/cgroup/system.slice

# 后序遍历
sudo ./src/62-iter-cgroup/iter-cgroup --order post
```

## 输出示例

```
# ./iter-cgroup 
=== Cgroup Hierarchy (root=/sys/fs/cgroup, order=pre) ===
id       level  nrdesc   path
1        0      69       /
31       1      0        /init.scope
75       1      35       /system.slice
798      2      0        /system.slice/system-modprobe.slice
974      2      0        /system.slice/sysroot.mount
1331     2      1        /system.slice/system-serial\x2dgetty.slice
5249     3      0        /system.slice/system-serial\x2dgetty.slice/serial-getty@ttyAMA0.service
1382     2      0        /system.slice/system-systemd\x2dfsck.slice
1433     2      0        /system.slice/system-xfs_scrub.slice
2286     2      0        /system.slice/swap.img.swap
2592     2      0        /system.slice/tmp.mount
2954     2      0        /system.slice/boot.mount
3005     2      0        /system.slice/boot-efi.mount
3515     2      0        /system.slice/lxd-installer.socket
3566     2      0        /system.slice/snapd.socket
3617     2      0        /system.slice/ssh.socket
3770     2      0        /system.slice/dbus.service
4127     2      0        /system.slice/networkd-dispatcher.service
4433     2      0        /system.slice/systemd-logind.service
4688     2      0        /system.slice/unattended-upgrades.service
4892     2      0        /system.slice/cron.service
5344     2      1        /system.slice/system-getty.slice
5395     3      0        /system.slice/system-getty.slice/getty@tty1.service
65447    2      0        /system.slice/systemd-journald.service
65498    2      0        /system.slice/systemd-networkd.service
65651    2      1        /system.slice/systemd-udevd.service
65702    3      0        /system.slice/systemd-udevd.service/udev
65721    2      0        /system.slice/systemd-resolved.service
65918    2      0        /system.slice/ssh.service
65969    2      0        /system.slice/multipathd.service
66020    2      0        /system.slice/rsyslog.service
66122    2      0        /system.slice/udisks2.service
66173    2      0        /system.slice/polkit.service
66224    2      0        /system.slice/ModemManager.service
66275    2      0        /system.slice/mariadb.service
137185   2      0        /system.slice/chrony.service
137943   2      0        /system.slice/nginx.service
148958   2      0        /system.slice/fwupd.service
842      1      0        /sys-kernel-config.mount
1484     1      18       /user.slice
5490     2      17       /user.slice/user-1000.slice
5592     3      6        /user.slice/user-1000.slice/user@1000.service
5643     4      0        /user.slice/user-1000.slice/user@1000.service/init.scope
5694     4      4        /user.slice/user-1000.slice/user@1000.service/app.slice
5745     5      0        /user.slice/user-1000.slice/user@1000.service/app.slice/dbus.socket
5789     5      0        /user.slice/user-1000.slice/user@1000.service/app.slice/gpg-agent-ssh.socket
5833     5      0        /user.slice/user-1000.slice/user@1000.service/app.slice/gpg-agent.socket
5877     5      0        /user.slice/user-1000.slice/user@1000.service/app.slice/ssh-agent.socket
6074     3      0        /user.slice/user-1000.slice/session-4.scope
6125     3      0        /user.slice/user-1000.slice/session-5.scope
6176     3      0        /user.slice/user-1000.slice/session-6.scope
6380     3      0        /user.slice/user-1000.slice/session-7.scope
6730     3      0        /user.slice/user-1000.slice/session-8.scope
7940     3      0        /user.slice/user-1000.slice/session-12.scope
17861    3      0        /user.slice/user-1000.slice/session-33.scope
17912    3      0        /user.slice/user-1000.slice/session-34.scope
17963    3      0        /user.slice/user-1000.slice/session-35.scope
39198    3      0        /user.slice/user-1000.slice/session-84.scope
1535     1      0        /dev-hugepages.mount
1586     1      0        /dev-mqueue.mount
1637     1      0        /sys-kernel-debug.mount
1688     1      0        /sys-kernel-tracing.mount
2031     1      0        /sys-fs-fuse-connections.mount
3464     1      0        /proc-sys-fs-binfmt_misc.mount
127066   1      3        /ai_inference
127117   2      0        /ai_inference/tenant_a
127136   2      0        /ai_inference/tenant_b
127647   2      0        /ai_inference/high_test
127686   1      1        /ai_inference.slice
127737   2      0        /ai_inference.slice/ai_inference-high_test.slice
```

## 教学概念

| 概念 | 说明 |
|---|---|
| `SEC("iter/cgroup")` | cgroup iterator 程序 |
| `bpf_iter__cgroup` 上下文 | 包含 `meta` + `cgroup` 指针 |
| `bpf_iter_attach_opts` | 必须指定 `cgroup.order` + `cgroup.cgroup_fd` |
| `BPF_CGROUP_ITER_DESCENDANTS_PRE` | 前序遍历后代（根→子→孙） |
| `bpf_probe_read_kernel_str` | 读取内核字符串（`kn->name`）到栈缓冲区 |
| `BPF_CORE_READ` | CO-RE 读取 `cgroup`/`kernfs_node` 结构体字段 |
