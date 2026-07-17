# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# 43-kfuncs: BPF part uses common.mk; the kernel module has its own Makefile
# in kernel/.  Build both on 'all'.
APP := kfuncs
include $(CURDIR)/../../common.mk

# Add module build as an order-only prereq (so it doesn't enter the link line).
$(APP): | module

.PHONY: module
module:
	$(Q)$(MAKE) -C $(CURDIR)/kernel 2>/dev/null || \
	 echo "  (kernel module build skipped/failed — needs kernel headers)"

clean: clean-mod
.PHONY: clean-mod
clean-mod:
	$(Q)$(MAKE) -C $(CURDIR)/kernel clean 2>/dev/null || true
