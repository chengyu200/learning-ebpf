# 35-user-ringbuf — 用户态→内核异步通信 (user ringbuf)

BPF_MAP_TYPE_USER_RINGBUF：用户态写入，BPF perf_event 程序用 bpf_user_ringbuf_drain 周期排空并打印。

## 运行
```bash
make -C src/35-user-ringbuf
sudo ./src/35-user-ringbuf/user-ringbuf
```
