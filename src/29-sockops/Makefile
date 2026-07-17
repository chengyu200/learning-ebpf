# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# 29-sockops: two BPF objects (bpf_contrack sockops + bpf_redirect sk_msg)
# sharing one SOCKHASH map, plus a single user-space binary.
APP := bpf_contrack
include $(CURDIR)/../../common.mk

# Extra dependency: the user-space object also needs the redirect skeleton
# (common.mk's generic %.skel.h rule builds bpf_redirect.skel.h too).
$(OUTPUT)/$(APP).o: $(OUTPUT)/bpf_redirect.skel.h
