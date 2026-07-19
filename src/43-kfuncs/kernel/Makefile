# SPDX-License-Identifier: GPL-2.0
obj-m += bpf_kfunc_demo.o

# 模块 BTF 生成需要 vmlinux ELF 文件（含 .BTF 段）。
# 运行内核没有 vmlinux 二进制文件（只有 headers），kbuild 会跳过 BTF 生成。
# 解决：从 /sys/kernel/btf/vmlinux（raw BTF）创建一个 ELF 格式的 fake vmlinux。
KDIR ?= /lib/modules/$(shell uname -r)/build
VMLINUX := $(KDIR)/vmlinux

all: $(VMLINUX) btf_vmlinux
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
	@echo "=== .ko BTF 段检查 ==="
	@readelf -S bpf_kfunc_demo.ko | grep -q '\.BTF ' && echo "BTF: OK" || echo "BTF: MISSING (kfunc registration will fail)"

# 如果 vmlinux 不存在，从 /sys/kernel/btf/vmlinux 创建一个含 .BTF 段的 ELF
$(VMLINUX):
	@echo "Creating fake vmlinux with BTF from /sys/kernel/btf/vmlinux..."
	@echo "" | gcc -c -x c - -o /tmp/_empty_elf.o 2>/dev/null
	@objcopy --add-section .BTF=/sys/kernel/btf/vmlinux /tmp/_empty_elf.o $(VMLINUX) 2>/dev/null
	@rm -f /tmp/_empty_elf.o

.PHONY: btf_vmlinux
btf_vmlinux: $(VMLINUX)

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
