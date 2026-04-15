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
#include "nova_skel.h"

struct nova_queue {
	struct nova_bpf	*nova_bpf;
};

static int	nova_queue_populate(struct quark_queue *);
static int	nova_queue_update_stats(struct quark_queue *);
static void	nova_queue_close(struct quark_queue *);

struct quark_queue_ops queue_ops_nova = {
	.open	      = nova_queue_open,
	.populate     = nova_queue_populate,
	.update_stats = nova_queue_update_stats,
	.close	      = nova_queue_close,
};

int
nova_queue_open(struct quark_queue *qq)
{
	struct nova_queue	*nqq;

	if ((qq->flags & QQ_NOVA) == 0)
		return (errno = ENOTSUP, -1);

	if ((nqq = calloc(1, sizeof(*nqq))) == NULL)
		return (-1);
	if ((nqq->nova_bpf = nova_bpf__open_and_load()) == NULL)
		goto fail;

	qq->queue_be = nqq;
	qq->queue_ops = &queue_ops_nova;
	qq->stats.backend = QQ_NOVA;

	return (0);
fail:
	nova_queue_close(qq);
	return (-1);
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
	struct nova_queue	*nqq = qq->queue_be;

	if (nqq == NULL)
		return;

	nova_bpf__destroy(nqq->nova_bpf);
	free(nqq);
	qq->queue_be = NULL;
}
