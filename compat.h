/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2024 Elastic NV */

#ifndef _COMPAT_H_
#define _COMPAT_H_

/* Linux specific */
#include <linux/types.h>

/* Sys */
#include <sys/types.h>

/* Standard */
#include <stdint.h>

/*
 * General compat
 */
/* uint64_t is historically defined as unsigned long on LONG architectures, not
 * unsigned long long, meaning we can't always use %llu for printing on 32 and
 * 64bit. We use __u64 which is saner.
 */
typedef __u64		u64;
typedef __s64		s64;
typedef __u32		u32;
typedef __s32		s32;
typedef __u16		u16;
typedef __s16		s16;
typedef __u8		u8;
typedef __s8		s8;
typedef uintptr_t	__uintptr_t;	/* for freebsd_tree.h */

#ifndef __aligned
#define __aligned(x)	__attribute__((aligned(x)))
#endif	/* __aligned */

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif	/* likely */

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif	/* unlikely */

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif	/* nitems */

#ifndef min
#define min(_a, _b)	((_a) < (_b) ? (_a) : (_b))
#endif	/* min */

/*
 * BSD compat
 */
#include "freebsd_queue.h"
#include "freebsd_tree.h"

size_t		strlcat(char *, const char *, size_t);
size_t		strlcpy(char *, const char *, size_t);
long long	strtonum(const char *, long long, long long, const char **);

#endif	/* _COMPAT_H */
