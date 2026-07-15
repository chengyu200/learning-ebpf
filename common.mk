# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Shared build rules for all eBPF examples.
#
# Each example's Makefile should set:
#   APP := <binary-name>
# And then: include $(CURDIR)/../../common.mk
#
# Source files (placed next to the example Makefile):
#   <APP>.bpf.c   kernel-side eBPF program
#   <APP>.c        user-space program
#   <APP>.h        shared header (optional)
#
# Required variables provided by the top-level Makefile / environment:
#   TOP_DIR        absolute path to repo root
#   BUILD_DIR      shared build output (.build under repo root)
#   LIBBPF_SRC / BPFTOOL_SRC / LIBBPF_OBJ / BPFTOOL / VMLINUX

CLANG       ?= clang
LLVM_STRIP  ?= llvm-strip
CC          ?= cc

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/aarch64.*/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

# Defaults for standalone builds (overridden by the top-level Makefile).
TOP_DIR ?= $(abspath $(CURDIR)/../..)
BUILD_DIR ?= $(TOP_DIR)/.build
LIBBPF_SRC ?= $(TOP_DIR)/libbpf/src
BPFTOOL_SRC ?= $(TOP_DIR)/bpftool/src
LIBBPF_OBJ ?= $(BUILD_DIR)/libbpf.a
BPFTOOL ?= $(BUILD_DIR)/bpftool/bootstrap/bpftool
VMLINUX ?= $(TOP_DIR)/vmlinux/$(ARCH)/vmlinux.h
OUTPUT      := $(BUILD_DIR)/$(APP)

INCLUDES := -I$(OUTPUT) -I$(BUILD_DIR) -I$(dir $(VMLINUX)) -I$(TOP_DIR)/src/common
CFLAGS   := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

LIBBPF_OBJDIR ?= $(BUILD_DIR)/libbpf
BPFTOOL_OUTPUT ?= $(BUILD_DIR)/bpftool

# Clang's default system include dirs, needed when compiling with -target bpf
# so that asm/types.h, asm/byteorder.h, sys/cdefs.h, etc. are found.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' \
		      "$(1)" \
		      "$(patsubst $(abspath $(BUILD_DIR))/%,%,$(2))" \
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all clean deps
all: $(APP)

# ---- Shared dependencies (libbpf.a + bpftool), built once into .build ----
deps: $(LIBBPF_OBJ) $(BPFTOOL)

$(LIBBPF_OBJDIR):
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_OBJDIR)
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) DESTDIR=$(BUILD_DIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BPFTOOL_OUTPUT):
	$(Q)mkdir -p $@

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Generate vmlinux.h from the running kernel's BTF (uses system bpftool).
$(VMLINUX):
	$(Q)mkdir -p $(dir $@)
	$(call msg,VMLINUX,$@)
	$(Q)bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@


clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APP)

# Build BPF object
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -fno-stack-protector -target bpf -D__TARGET_ARCH_$(ARCH) \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		     -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@

# Generate skeleton header
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# User-space object depends on the skeleton header of the same name
$(OUTPUT)/$(APP).o: $(APP).c $(wildcard $(APP).h) $(OUTPUT)/$(APP).skel.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Link final binary
$(APP): $(OUTPUT)/$(APP).o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

.DELETE_ON_ERROR:
.SECONDARY:
