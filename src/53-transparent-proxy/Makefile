# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# 53-transparent-proxy: 透明代理示例（双二进制）
#   sidecar = BPF loader + TCP 代理（含 .bpf.c → .skel.h 骨架）
#   server  = 纯 HTTP echo（无 BPF 依赖）
#
# common.mk 的模式规则自动构建 sidecar.bpf.o / sidecar.skel.h。
# 此处追加 server 的构建规则。

APP := sidecar
include $(CURDIR)/../../common.mk

all: sidecar server

# server 是纯 C 程序，无需 BPF；手动追加构建规则
server: $(OUTPUT)/server.o | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -o $@

$(OUTPUT)/server.o: server.c proxy.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) sidecar server

.PHONY: all clean
