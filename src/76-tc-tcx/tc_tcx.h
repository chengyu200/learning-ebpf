/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * 76-tc-tcx: TC/TCX 流量统计共享定义。
 */
#ifndef __TC_TCX_H
#define __TC_TCX_H

/* TCX return values (enum tcx_action_base, from linux/bpf.h) */
#define TCX_NEXT  (-1)  /* continue to next program in chain */
#define TCX_PASS  0     /* accept packet, stop chain */
#define TCX_DROP  2     /* drop packet, stop chain */

#define MAX_PKT_LEN 65535

struct pkt_info {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  proto;
	__u8  direction;  /* 0=ingress, 1=egress */
	__u16 pkt_len;
};

#endif /* __TC_TCX_H */
