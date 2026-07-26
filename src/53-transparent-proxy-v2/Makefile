# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# 53-transparent-proxy-v2: 透明代理示例（三二进制）
#   sidecar         = BPF loader + TCP 代理（含 .bpf.c → .skel.h）
#   server          = 纯 HTTP echo + /outbound 出连接
#   external-server = 在 bpfns netns 内监听 :9090
APP := sidecar
include $(CURDIR)/../../common.mk

all: sidecar server external-server

server: $(OUTPUT)/server.o | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -o $@

$(OUTPUT)/server.o: server.c proxy.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

external-server: $(OUTPUT)/external-server.o | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -o $@

$(OUTPUT)/external-server.o: external-server.c proxy.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) sidecar server external-server

.PHONY: all clean
