/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __UPROBE_RUST_H
#define __UPROBE_RUST_H

struct event {
	__u32 pid;
	__u64 ts_ns;
	__u64 arg;
};

#endif
