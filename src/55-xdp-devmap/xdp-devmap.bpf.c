// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 55-xdp-devmap: XDP DEVMAP forwarding + mirroring.
 *
 * Two BPF programs in one object:
 *   1. SEC("xdp")       — main program on ingress NIC (vethext0)
 *   2. SEC("xdp/devmap") — secondary program on egress NIC TX path (vethint0)
 *
 * Forward mode: packets to target_prefix are redirected via DEVMAP to the
 *   internal NIC; the devmap program rewrites MAC addresses.
 * Mirror mode: all IPv4 packets are broadcast (BPF_F_BROADCAST) to mirror_map;
 *   the devmap program counts them.
 *
 * Teaches: BPF_MAP_TYPE_DEVMAP, SEC("xdp/devmap"), bpf_redirect_map,
 *   BPF_F_BROADCAST, bpf_devmap_val, L3 forwarding MAC rewrite.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "xdp-devmap.h"

char LICENSE[] SEC("license") = "GPL";

/* ── Config (set from user space via rodata) ── */
const volatile __u32 target_prefix = 0;   /* network byte order, e.g. 0x0a020000 = 10.2.0.0 */
const volatile __u32 target_mask   = 0;   /* network byte order, e.g. 0xffffff00 = /24 */
const volatile bool  mirror_mode   = false;

/* ── DEVMAP for forwarding (key=0 → internal NIC) ── */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);
} forward_map SEC(".maps");

/* ── DEVMAP for mirroring (BPF_F_BROADCAST targets) ── */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);
} mirror_map SEC(".maps");

/* ── Stats (per-CPU array) ── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps");

/* ── MAC config (array, filled from user space) ── */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mac_config);
} mac_map SEC(".maps");

/* ── Main XDP program (ingress on vethext0) ── */
SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 pkt_len = data_end - data;

    /* Mirror mode: broadcast to all mirror_map entries */
    if (mirror_mode) {
        __u32 sk = STAT_MIRROR;
        struct stats *st = bpf_map_lookup_elem(&stats_map, &sk);
        if (st) {
            st->pkts++;
            st->bytes += pkt_len;
        }
        return bpf_redirect_map(&mirror_map, 0, BPF_F_BROADCAST);
    }

    /* Forward mode: match destination subnet */
    if (target_mask && (iph->daddr & target_mask) == target_prefix) {
        __u32 sk = STAT_FORWARD;
        struct stats *st = bpf_map_lookup_elem(&stats_map, &sk);
        if (st) {
            st->pkts++;
            st->bytes += pkt_len;
        }
        return bpf_redirect_map(&forward_map, 0, 0);
    }

    return XDP_PASS;
}

/* ── Secondary XDP program (runs on egress NIC TX path via DEVMAP) ── */
SEC("xdp/devmap")
int xdp_egress(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 zero = 0;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Rewrite MAC addresses for L3 forwarding */
    struct mac_config *mc = bpf_map_lookup_elem(&mac_map, &zero);
    if (mc) {
        __builtin_memcpy(eth->h_source, mc->src_mac, 6);
        __builtin_memcpy(eth->h_dest, mc->dst_mac, 6);
    }

    return XDP_PASS;
}
