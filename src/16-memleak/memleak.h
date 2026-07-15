/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define TASK_COMM_LEN 16
#define ALLOCS_MAX_ENTRIES 100000

struct alloc_info {
	__u64 size;
	__u64 stack_id;
	__u64 timestamp_ns;
};

#endif
