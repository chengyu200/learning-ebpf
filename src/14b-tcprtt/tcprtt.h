/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* 14b-tcprtt: shared definitions. */
#ifndef __TCPRTT_H
#define __TCPRTT_H

#define MAX_SLOTS    27          /* 2^0 .. 2^26, covers 0us .. ~67s */

#ifndef AF_INET
#define AF_INET      2
#endif
#ifndef AF_INET6
#define AF_INET6     10
#endif

/* Per-key histogram stored in the hists hash map. */
struct hist {
    __u64 slots[MAX_SLOTS];      /* log2 bucket counts */
    __u64 latency;               /* sum of srtt (for -e average) */
    __u64 cnt;                   /* sample count */
};

#endif /* __TCPRTT_H */
