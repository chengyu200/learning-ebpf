# 43-kfuncs — 自定义 kfunc (内核模块 + BPF)

构建一个内核模块 bpf_kfunc_demo.ko 注册 bpf_kfunc_greet kfunc，BPF 程序通过 __ksym 外部声明调用它。**最复杂示例。**

## 运行
```bash
make -C src/43-kfuncs
cd src/43-kfuncs/kernel && make && sudo insmod bpf_kfunc_demo.ko; sudo ./src/43-kfuncs/kfuncs
```
