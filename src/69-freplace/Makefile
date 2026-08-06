# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# 69-freplace: BPF 程序运行时热补丁（双二进制）
#   target = 目标 BPF 程序（含可替换函数 filter_check）
#   ext    = 扩展 BPF 程序（freplace 替换 filter_check）
#
# target.bpf.c 需要特殊的编译选项 -mllvm -inline-threshold=0 防止 filter_check 被内联。
# ext.bpf.c 使用标准编译选项。
APP := target
include $(CURDIR)/../../common.mk

all: target ext

# 覆盖 target.bpf.o 的编译规则：添加 -mllvm -inline-threshold=0
$(OUTPUT)/target.bpf.o: target.bpf.c $(LIBBPF_OBJ) $(wildcard target.h freplace.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -fno-stack-protector -target bpf -D__TARGET_ARCH_$(ARCH) \
		 -mllvm -inline-threshold=0 \
		 $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		 -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@

# ext 二进制（需要 libbpf.a）
ext: $(OUTPUT)/ext.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

$(OUTPUT)/ext.o: ext.c $(wildcard ext.h freplace.h) $(OUTPUT)/ext.skel.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) target ext

.PHONY: all clean
