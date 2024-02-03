#ifndef _COMPAT_H_
#define _COMPAT_H_

#include <sys/types.h>

#include <stdint.h>

/*
 * General compat
 */
#ifndef __aligned
#define __aligned(x)	__attribute__((aligned(x)))
#endif

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

#include "freebsd_queue.h"
typedef uintptr_t __uintptr_t;
#include "freebsd_tree.h"

/*
 * BSD compat
 */
size_t		strlcat(char *, const char *, size_t);
size_t		strlcpy(char *, const char *, size_t);
long long	strtonum(const char *, long long, long long, const char **);

#endif	/* _COMPAT_H */
