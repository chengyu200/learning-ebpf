/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __NGINX_H
#define __NGINX_H

struct event {
	__u32 pid;
	__u64 ts_ns;
	__u64 duration_ns;
};

#endif
