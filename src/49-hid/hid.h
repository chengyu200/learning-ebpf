/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __HID_H
#define __HID_H

struct event {
	__u32 pid;
	__u32 minor;   /* hidraw minor */
	__u64 ts_ns;
};

#endif
