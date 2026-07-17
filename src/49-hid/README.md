# 49-hid

通过 kprobe 追踪 HID（人机接口设备）报告事件。

## 做什么

- 内核态：在 `hidraw_report_event` 上挂 kprobe，捕获 HID 报告事件，将 {pid, minor, ts} 通过 ring buffer 发送到用户态。
- 用户态：轮询 ring buffer 打印 HID 事件。

## 教学概念

- HID 输入路径追踪（`hidraw_report_event`）。
- 本机已启用 `CONFIG_HID_BPF=y`，内核支持完整的 HID-BPF（struct_ops 方式），本示例用 kprobe 以保证可移植性。
- `hidraw` 设备（`/sys/class/hidraw/`）。

## 运行

```bash
make -C src/49-hid
sudo ./src/49-hid/hid
# 移动鼠标 / 按键触发 HID 事件
```
