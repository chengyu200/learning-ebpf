# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# 53-transparent-proxy-v4: 透明代理示例（端口一致 + PID 排除防回环）
#   sidecar         = BPF loader + TCP 代理（sk_lookup + connect4 + sockops + sk_msg）
#   server          = 纯 HTTP echo on 0.0.0.0:8080 + /outbound 出连接
#   external-server = 在 bpfns netns 内监听 :9090
APP := sidecar
EXTRA_LDFLAGS := -lpthread
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
