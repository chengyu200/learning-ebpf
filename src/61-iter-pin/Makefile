# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# 61-iter-pin: 只编译 BPF .o，不生成 skeleton/用户态二进制。
# 用 bpftool iter pin + cat 工作流。
APP := iter-pin

# 覆盖 common.mk 的 all 目标：只编译 .bpf.o
CLANG       ?= clang
LLVM_STRIP  ?= llvm-strip

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/aarch64.*/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

TOP_DIR ?= $(abspath $(CURDIR)/../..)
BUILD_DIR ?= $(TOP_DIR)/.build
LIBBPF_SRC ?= $(TOP_DIR)/libbpf/src
LIBBPF_OBJ ?= $(BUILD_DIR)/libbpf.a
BPFTOOL ?= $(BUILD_DIR)/bpftool/bootstrap/bpftool
VMLINUX ?= $(TOP_DIR)/vmlinux/$(ARCH)/vmlinux.h
OUTPUT := $(BUILD_DIR)/$(APP)

INCLUDES := -I$(OUTPUT) -I$(BUILD_DIR) -I$(dir $(VMLINUX)) -I$(TOP_DIR)/src/common

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all clean deps

all: $(APP).bpf.o

deps: $(LIBBPF_OBJ) $(BPFTOOL) $(VMLINUX)

$(LIBBPF_OBJ):
	@$(MAKE) -C $(TOP_DIR) deps

$(BPFTOOL):
	@$(MAKE) -C $(TOP_DIR) deps

$(VMLINUX):
	@$(MAKE) -C $(TOP_DIR) vmlinux

$(APP).bpf.o: $(APP).bpf.c $(LIBBPF_OBJ) $(wildcard $(APP).h) $(VMLINUX)
	$(CLANG) -g -O2 -fno-stack-protector -target bpf -D__TARGET_ARCH_$(ARCH) \
		 $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		 -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(APP).bpf.o
