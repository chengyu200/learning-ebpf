// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 14b-tcprtt: kernel-side BPF program.
 *
 * Attach to fentry/tcp_rcv_established, read tcp_sock->srtt_us (smoothed
 * RTT), bucket it into a log2 histogram keyed by address (or 0 = global).
 *
 * Teaches: fentry + BPF_PROG, BPF_CORE_READ on nested structs,
 * BPF_MAP_TYPE_HASH with struct value, log2 bucketing.
 *
 * fentry is preferred over kprobe: it uses BPF trampoline (no probe
 * overhead), gets typed arguments directly (no pt_regs parsing), and
 * has BTF type safety. Requires CONFIG_DEBUG_INFO_BTF + CONFIG_FUNCTION_TRACER.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tcprtt.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ── Filter config (set from user space via rodata) ── */
const volatile __u16 targ_sport = 0;   /* host byte order, 0 = no filter */
const volatile __u16 targ_dport = 0;
const volatile __u32 targ_saddr = 0;   /* network byte order */
const volatile __u32 targ_daddr = 0;
const volatile short targ_family = 0;  /* 0 = both */
const volatile bool targ_ms = false;   /* show milliseconds */
const volatile bool targ_laddr_hist = false;  /* histogram by local addr */
const volatile bool targ_raddr_hist = false;  /* histogram by remote addr */
const volatile bool targ_show_ext = false;    /* show average */

/* ── Histogram map: key = address (0=global), value = struct hist ── */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

/* log2l for u64 — returns floor(log2(x)), 0 if x==0 */
static inline __u64 log2l_u64(__u64 v)
{
    if (v == 0)
        return 0;
    return 63 - __builtin_clzll(v);
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    struct tcp_sock *ts;
    struct hist *hp;
    __u64 key, slot;
    __u32 srtt;
    __u16 sport, dport, family;
    __u32 saddr, daddr;

    if (!sk)
        return 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (targ_family && targ_family != family)
        return 0;

    sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
    dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (targ_sport && targ_sport != sport)
        return 0;
    if (targ_dport && targ_dport != dport)
        return 0;

    if (family == AF_INET) {
        saddr = BPF_CORE_READ(inet, inet_saddr);
        daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else {
        saddr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]);
        daddr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
    }

    if (targ_saddr && targ_saddr != saddr)
        return 0;
    if (targ_daddr && targ_daddr != daddr)
        return 0;

    /* Select histogram key: by local addr, by remote addr, or global */
    if (targ_laddr_hist)
        key = saddr;
    else if (targ_raddr_hist)
        key = daddr;
    else
        key = 0;

    hp = bpf_map_lookup_elem(&hists, &key);
    if (!hp) {
        bpf_map_update_elem(&hists, &key, &zero, BPF_ANY);
        hp = bpf_map_lookup_elem(&hists, &key);
        if (!hp)
            return 0;
    }

    /* srtt_us is stored as (actual_srtt << 3) inside the kernel */
    ts = (struct tcp_sock *)sk;
    srtt = BPF_CORE_READ(ts, srtt_us) >> 3;

    if (targ_ms)
        srtt /= 1000U;

    slot = log2l_u64(srtt);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    __sync_fetch_and_add(&hp->slots[slot], 1);

    if (targ_show_ext) {
        __sync_fetch_and_add(&hp->latency, srtt);
        __sync_fetch_and_add(&hp->cnt, 1);
    }

    return 0;
}
