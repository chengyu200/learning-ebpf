# features/bpf_iters

bpf_iter 程序：遍历内核数据结构（如 task），通过 seq_file 导出。

## 运行
```bash
make -C src/features/bpf_iters
sudo ./src/features/bpf_iters/iters
```
