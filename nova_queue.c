// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#include <sys/epoll.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/sysinfo.h>

#include <assert.h>
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

/*
 * Alloc a path_lpm_key inside the probe, keyed by rule number + field type +
 * path.
 */
static int
alloc_path(struct nova_queue *nqq, int rule_i, struct quark_rule_field *field)
{
	struct path_lpm_key	key;
	u64			v = 1;

	if (strlen(field->wild.pre) >= NOVA_PATHLEN ||
	    strlen(field->wild.post) >= NOVA_PATHLEN)
		return (errno = E2BIG, -1);

	if (field->wild.post_len != 0)
		return (errno = ENOTSUP, -1);

	bzero(&key, sizeof(key));

#ifdef HAVE_STATIC_ASSERT
	static_assert((NOVA_MAX_RULES - 1) <= (META_RULE_MSK >> META_RULE_SHIFT),
	    "NOVA_MAX_RULES cannot fit in META_RULE_MSK");
#endif

	switch (field->code) {
	case QUARK_RF_EXE:
		key.meta = META_MAKE(rule_i, META_RF_EXE);
		break;
	case QUARK_RF_FILEPATH:
		key.meta = META_MAKE(rule_i, META_RF_FILEPATH);
		break;
	default:
		qwarnx("unhandled code %llu", field->code);
		return (-1);
	}

	/*
	 * Calculate prefixlen, we always include at least key.meta, and then
	 * add pre_len
	 */
	key.prefixlen = (sizeof(key.meta) + field->wild.pre_len) * 8;

	if (strlcpy(key.path, field->wild.pre, sizeof(key.path)) >= sizeof(key.path))
		return (errno = E2BIG, -1);

	if (bpf_map__update_elem(nqq->nova_bpf->maps.lpm_path,
	    &key, sizeof(key), &v, sizeof(v), BPF_ANY) != 0) {
		qwarn("bpf_map__update_elem %d", rule_i);
		return (-1);
	}

	return (0);
}

static int
nova_rule_from_quark(struct nova_queue *nqq,
    struct nova_rule *nr, struct quark_rule *qr)
{
	size_t			 i;
	struct quark_rule_field *field;

	bzero(nr, sizeof(*nr));

	for (i = 0; i < qr->n_fields; i++) {
		field = qr->fields + i;

		switch (field->code) {
		case QUARK_RF_PID:
			nr->pid = field->id;
			break;
		case QUARK_RF_PPID:
			nr->ppid = field->id;
			break;
		case QUARK_RF_UID:
			nr->uid = field->id;
			break;
		case QUARK_RF_GID:
			nr->gid = field->id;
			break;
		case QUARK_RF_SID:
			nr->sid = field->id;
			break;
		case QUARK_RF_COMM:
			strlcpy(nr->comm, field->comm, sizeof(nr->comm));
			break;
		case QUARK_RF_EXE:
			if ((alloc_path(nqq, qr->number, field)) == -1) {
				qwarn("exe alloc_path");
				return (-1);
			}
			break;
		case QUARK_RF_FILEPATH:
			if ((alloc_path(nqq, qr->number, field)) == -1) {
				qwarn("file_path alloc_path");
				return (-1);
			}
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

	nr->number = qr->number;
	nr->action = qr->action;

	return (0);
}

static int
load_rodata(struct quark_queue *qq, struct nova_queue *nqq)
{
	if (qq->ruleset == NULL)
		return (0);
	if (qq->ruleset->n_rules > NOVA_MAX_RULES)
		return (errno = EFBIG, -1);

	nqq->nova_bpf->rodata->rules_active = qq->ruleset->n_rules;

	return (0);
}

/*
 * Walk over all rules, make a nova_rule{} out of a quark_rule{} and install it
 * in the bpf rule map.
 */
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
	if (qq->ruleset->n_rules != nqq->nova_bpf->rodata->rules_active)
		return (errno = EINVAL, -1);
	if ((nova_bpf = nqq->nova_bpf) == NULL)
		return (errno = EINVAL, -1);

	for (i = 0; i < (u32)qq->ruleset->n_rules; i++) {
		if (nova_rule_from_quark(nqq, &nr,
		    qq->ruleset->rules + i) == -1) {
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
	qq->queue_be = nqq;

	if ((nqq->nova_bpf = nova_bpf__open()) == NULL)
		goto fail;
	if (load_rodata(qq, nqq) == -1)
		goto fail;
	if (nova_bpf__load(nqq->nova_bpf) != 0)
		goto fail;
	if (load_ruleset(qq, nqq) == -1)
		goto fail;
	if (nova_bpf__attach(nqq->nova_bpf) != 0)
		goto fail;

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
	struct nova_queue	*nqq	  = qq->queue_be;
	struct nova_bpf		*nova_bpf = nqq->nova_bpf;
	struct nova_rule_pcpu	*rule_pcpu;
	int			 num_cpus;
	struct quark_rule	*qr;
	u32			 i;
	int			 j;

	if (qq->ruleset == NULL)
		return (0);

	if ((num_cpus = libbpf_num_possible_cpus()) <= 0) {
		qwarnx("bad libbpf_num_possible_cpus: %d", num_cpus);
		return (-1);
	}
	if ((rule_pcpu = calloc(num_cpus, sizeof(*rule_pcpu))) == NULL) {
		qwarn("calloc");
		return (-1);
	}
#ifdef HAVE_STATIC_ASSERT
	static_assert(sizeof(*rule_pcpu) % 8 == 0,
	    "struct nova_rule_pcpu must be 8 byte aligned");
#endif

	for (i = 0; i < (u32)qq->ruleset->n_rules; i++) {
		qr = qq->ruleset->rules + i;

		qr->evals = 0;
		qr->hits = 0;

		if (bpf_map__lookup_elem(nova_bpf->maps.ruleset_pcpu, &i,
		    sizeof(i), rule_pcpu, sizeof(*rule_pcpu) * num_cpus, 0) != 0) {
			qwarn("bpf_map__lookup_elem");
			goto fail;
		}

		for (j = 0; j < num_cpus; j++) {
			qr->evals += rule_pcpu[j].evals;
			qr->hits += rule_pcpu[j].hits;
		}
	}

	free(rule_pcpu);

	return (0);
fail:
	free(rule_pcpu);

	return (-1);
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
