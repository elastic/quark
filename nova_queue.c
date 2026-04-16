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

static int
nova_rule_from_quark(struct nova_rule *nr, struct quark_rule *qr)
{
	size_t			 i;
	struct quark_rule_field *field;

	bzero(nr, sizeof(*nr));

	for (i = 0; i < qr->n_fields; i++) {
		field = qr->fields + i;

		switch (field->code) {
		case QUARK_RF_PROCESS_PID:
			nr->pid = field->id;
			break;
		case QUARK_RF_PROCESS_PPID:
			nr->ppid = field->id;
			break;
		case QUARK_RF_PROCESS_UID:
			nr->uid = field->id;
			break;
		case QUARK_RF_PROCESS_GID:
			nr->gid = field->id;
			break;
		case QUARK_RF_PROCESS_SID:
			nr->sid = field->id;
			break;
		case QUARK_RF_PROCESS_COMM:
			strlcpy(nr->comm, field->comm, sizeof(nr->comm));
			break;
		case QUARK_RF_PROCESS_FILENAME:
			/* TODO */
			errno = ENOTSUP;
			qwarn("QUARK_RF_PROCESS_FILENAME");
			return (-1);
			break;
		case QUARK_RF_FILE_PATH:
			/* TODO */
			errno = ENOTSUP;
			qwarn("QUARK_RF_FILE_PATH");
			return (-1);
			break;
		case QUARK_RF_POISON:
			nr->poison_tag = field->poison_tag;
			break;
		default:
			errno = EINVAL;
			qwarn("bad field->code %llu", field->code);
			return (-1);
			break;
		}

		nr->fields |= field->code;
	}

	nr->action = qr->action;

	return (0);
}

static int
load_ruleset(struct quark_queue *qq, struct nova_queue *nqq)
{
	u32			 i;
	struct nova_bpf		*nova_bpf;
	struct nova_rule	 nr;

	if (qq->ruleset == NULL)
		return (0);
	if (qq->ruleset->n_rules > NOVA_MAX_RULES)
		return (errno = EFBIG, -1);
	if ((nova_bpf = nqq->nova_bpf) == NULL)
		return (errno = EINVAL, -1);

	for (i = 0; i < (u32)qq->ruleset->n_rules; i++) {
		if (nova_rule_from_quark(&nr, qq->ruleset->rules + i) == -1) {
			qwarn("quark_rule_to_nova");
			return (-1);
		}
		if (bpf_map__update_elem(nova_bpf->maps.ruleset, &i, sizeof(i),
		    &nr, sizeof(nr), BPF_ANY) != 0) {
			qwarn("bpf_map__update_elem %d", i);
			return (-1);
		}
	}

	return (0);
}

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
	if (load_ruleset(qq, nqq) == -1)
		goto fail;
	if (nova_bpf__attach(nqq->nova_bpf) != 0)
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
