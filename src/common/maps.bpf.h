/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Shared BPF-side helpers (compiled with -target bpf). */
#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include <bpf/bpf_helpers.h>

/* Lookup a key; if absent, insert the given init value and return the entry. */
static inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	long err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	/* -EEXIST (17) is fine: another CPU raced ahead; fall through to lookup. */
	if (err && err != -17)
		return 0;

	return bpf_map_lookup_elem(map, key);
}

#endif /* __MAPS_BPF_H */
