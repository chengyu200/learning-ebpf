/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __HARDIRQS_H
#define __HARDIRQS_H

struct irq_stat {
	unsigned long long total_ns;
	unsigned long long count;
};

#endif /* __HARDIRQS_H */
