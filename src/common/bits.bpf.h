/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Shared BPF-side bit/log helpers (compiled with -target bpf). */
#ifndef __BITS_BPF_H
#define __BITS_BPF_H

#include <bpf/bpf_helpers.h>

/* Largest power of two <= value; 0 if value is 0. Useful for log2 histograms. */
static inline __u64 log2l(__u64 v)
{
	__u64 r = 0;

	if (v >> 32)
		v >>= 32, r |= 32;
	if (v >> 16)
		v >>= 16, r |= 16;
	if (v >> 8)
		v >>= 8, r |= 8;
	if (v >> 4)
		v >>= 4, r |= 4;
	if (v >> 2)
		v >>= 2, r |= 2;
	if (v >> 1)
		v >>= 1, r |= 1;
	return r;
}

#endif /* __BITS_BPF_H */
