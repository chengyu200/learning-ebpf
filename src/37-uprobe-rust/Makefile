# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
APP := uprobe-rust
include $(CURDIR)/../../common.mk

# Build the small Rust target (uprobe victim) before the binary, but as an
# order-only prerequisite so it isn't passed to the linker.
$(APP): | target

target: target.rs
	$(call msg,RUSTC,$@)
	@rustc -g target.rs -o target 2>&1 || \
	 echo "  note: build manually with: rustc -g target.rs -o target"

clean: clean-rust
.PHONY: clean-rust
clean-rust:
	$(Q)rm -f target
