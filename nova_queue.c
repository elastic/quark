// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#include <sys/epoll.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/sysinfo.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/btf.h>

#include "quark.h"
/* #include "nova_skel.h" */

struct nova_queue {
	void	*nada;
};

static int	nova_queue_populate(struct quark_queue *);
static int	nova_queue_update_stats(struct quark_queue *);
static void	nova_queue_close(struct quark_queue *);

struct quark_queue_ops queue_ops_qbpf = {
	.open	      = nova_queue_open,
	.populate     = nova_queue_populate,
	.update_stats = nova_queue_update_stats,
	.close	      = nova_queue_close,
};

int
nova_queue_open(struct quark_queue *qq)
{
#ifdef notyet
	if ((qq->flags & QQ_NOVA) == 0)
		return (errno = ENOTSUP, -1);

	return (0);
#endif
	return (errno = ENOTSUP, -1);
}

static int
nova_queue_populate(struct quark_queue *qq)
{
	return (0);
}

static int
nova_queue_update_stats(struct quark_queue *qq)
{
	return (0);
}

static void
nova_queue_close(struct quark_queue *qq)
{
	/* NADA */
}
