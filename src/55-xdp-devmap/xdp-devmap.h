/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* 55-xdp-devmap: shared definitions. */
#ifndef __XDP_DEVMAP_H
#define __XDP_DEVMAP_H

#define ETH_P_IP 0x0800

/* Stats indices */
#define STAT_FORWARD  0
#define STAT_MIRROR   1

struct stats {
    __u64 pkts;
    __u64 bytes;
};

/* MAC config for egress rewrite: [0..5]=src_mac, [6..11]=dst_mac */
struct mac_config {
    __u8 src_mac[6];
    __u8 dst_mac[6];
};

#endif /* __XDP_DEVMAP_H */
