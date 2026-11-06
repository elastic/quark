/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2024-2026 Elastic NV */

/*
 * Library internals shared by quark.c, the backends and the in-tree
 * utilities, not part of the installed API. Everything here may change
 * without notice.
 */

#ifndef _QUARK_INTERNAL_H_
#define _QUARK_INTERNAL_H_

#include <time.h>

#include "compat.h"

#ifndef ALIGN_UP
#define ALIGN_UP(_p, _b) (((u64)(_p) + ((_b) - 1)) & ~((_b) - 1))
#endif

/*
 * Time helpers
 */
#ifndef NS_PER_S
#define NS_PER_S	1000000000ULL
#endif /* NS_PER_S */

#ifndef NS_PER_MS
#define NS_PER_MS	1000000ULL
#endif /* NS_PER_MS */

#ifndef MS_TO_NS
#define MS_TO_NS(_x)	((u64)(_x) * NS_PER_MS)
#endif /* MS_TO_NS */

#ifndef TS_TO_NS
#define TS_TO_NS(_ts) ((u64)(_ts).tv_sec * NS_PER_S + (u64)(_ts).tv_nsec)
#endif /* TS_TO_NS */

#ifndef NS_TO_S
#define NS_TO_S(_x)	((u64)(_x) / NS_PER_S)
#endif /* NS_TO_S */

/*
 * How long after flipping the UDP flow generation before the inactive map is
 * drained. A cgroup_skb program reads the generation and updates the map
 * within one run, a handful of microseconds, this is a wide margin over
 * that. Also the tail of a flow's delivery latency, see udp_idle_expire().
 */
#define UDP_FLOW_FLIP_GRACE	MS_TO_NS(100)

/*
 * CLOCK_BOOTTIME in nanoseconds.
 * Zero if the clock can't be read (should never happen).
 */
static inline u64
now64(void)
{
	struct timespec	ts;

	if (clock_gettime(CLOCK_BOOTTIME, &ts) == -1)
		return (0);

	return (TS_TO_NS(ts));
}

#endif /* _QUARK_INTERNAL_H_ */
