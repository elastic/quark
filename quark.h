#ifndef _QUARK_H_

#define _QUARK_H_

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

#endif /* _QUARK_H_ */
