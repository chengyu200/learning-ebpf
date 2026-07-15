# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Top-level Makefile for the eBPF learning repository.

TOP_DIR    := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_DIR  := $(TOP_DIR)/.build
LIBBPF_SRC := $(TOP_DIR)/libbpf/src
BPFTOOL_SRC := $(TOP_DIR)/bpftool/src
LIBBPF_OBJ := $(BUILD_DIR)/libbpf.a
LIBBPF_OBJDIR := $(BUILD_DIR)/libbpf
BPFTOOL_OUTPUT := $(BUILD_DIR)/bpftool
BPFTOOL := $(BPFTOOL_OUTPUT)/bootstrap/bpftool

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/aarch64.*/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := $(TOP_DIR)/vmlinux/$(ARCH)/vmlinux.h

# Every directory under src/ that contains a Makefile is an example.
EXAMPLE_DIRS := $(patsubst %/,%,$(dir $(wildcard $(TOP_DIR)/src/*/Makefile)))

.DEFAULT_GOAL := all
.PHONY: all deps vmlinux clean install help

all: deps vmlinux
	@for d in $(EXAMPLE_DIRS); do \
		echo "==> $$(basename $$d)"; \
		$(MAKE) -C $$d TOP_DIR=$(TOP_DIR) BUILD_DIR=$(BUILD_DIR) \
			LIBBPF_SRC=$(LIBBPF_SRC) BPFTOOL_SRC=$(BPFTOOL_SRC) \
			LIBBPF_OBJ=$(LIBBPF_OBJ) BPFTOOL=$(BPFTOOL) VMLINUX=$(VMLINUX) \
			|| exit 1; \
	done

# Build libbpf.a and bpftool once into the shared .build directory.
deps: $(LIBBPF_OBJ) $(BPFTOOL)

$(LIBBPF_OBJDIR):
	@mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_OBJDIR)
	@echo "  LIB      libbpf"
	@$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) DESTDIR=$(BUILD_DIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BPFTOOL):
	@mkdir -p $(BPFTOOL_OUTPUT)
	@echo "  BPFTOOL  bpftool"
	@$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Generate vmlinux.h from the running kernel's BTF.
vmlinux: $(VMLINUX)

$(VMLINUX):
	@mkdir -p $(dir $@)
	@echo "  VMLINUX  $@"
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	@for d in $(EXAMPLE_DIRS); do $(MAKE) -C $$d clean || true; done
	@rm -rf $(BUILD_DIR)

install:
	sudo apt-get update
	sudo apt-get install -y --no-install-recommends \
		libelf1 libelf-dev zlib1g-dev libssl-dev \
		make clang llvm iproute2

help:
	@echo "Targets:"
	@echo "  make          build all examples"
	@echo "  make install  install build dependencies (Debian/Ubuntu)"
	@echo "  make clean     remove all build artifacts"
	@echo "First time: git submodule update --init --recursive"
