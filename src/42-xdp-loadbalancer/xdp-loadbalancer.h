/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __XDP_LB_H
#define __XDP_LB_H

#define MAX_BACKENDS 8

struct backend {
	__u32 addr;       /* network order */
	__u8 mac[6];      /* target MAC */
};

#endif
