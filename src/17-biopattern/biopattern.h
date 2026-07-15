/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2020 Wenbo Zhang */
#ifndef __BIOPATTERN_H
#define __BIOPATTERN_H

struct counter {
	__u64 last_sector;
	__u64 sequential;
	__u64 random;
	__u64 bytes;
};

#endif
