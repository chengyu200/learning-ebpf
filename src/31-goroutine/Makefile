# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
APP := goroutine
include $(CURDIR)/../../common.mk

# Build a small Go program to trace (order-only prereq).
$(APP): | gotest

gotest: gotest.go
	$(call msg,GO,$@)
	@go build -o gotest gotest.go 2>&1 || \
	 echo "  note: build manually with: go build -o gotest gotest.go"

clean: clean-go
.PHONY: clean-go
clean-go:
	$(Q)rm -f gotest
