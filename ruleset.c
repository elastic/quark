// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024-2026 Elastic NV */

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "quark.h"

void
quark_ruleset_init(struct quark_ruleset *ruleset)
{
	bzero(ruleset, sizeof(*ruleset));
}

/* Free what rule_field_validate() allocated for one value */
static void
rule_field_free(struct quark_rule_field *rf)
{
	switch (rf->code) {
	case QUARK_RF_FILEPATH:		/* FALLTHROUGH */
	case QUARK_RF_EXE:		/* FALLTHROUGH */
	case QUARK_RF_POD_NAME:		/* FALLTHROUGH */
	case QUARK_RF_CONTAINER_IMAGE:
		free(rf->wild.pre);
		rf->wild.pre = NULL;
		break;
	default:
		break;
	}
}

void
quark_ruleset_clear(struct quark_ruleset *ruleset)
{
	struct quark_rule	*rule;
	struct quark_rule_cond	*cond;
	size_t			 i, j, k;

	for (i = 0; i < ruleset->n_rules; i++) {
		rule = ruleset->rules + i;
		for (j = 0; j < rule->n_conds; j++) {
			cond = rule->conds + j;
			for (k = 0; k < cond->n_values; k++)
				rule_field_free(cond->values + k);
			free(cond->values);
		}
		free(rule->conds);
	}

	free(ruleset->rules);
	ruleset->rules = NULL;
	ruleset->n_rules = 0;
}

int
quark_ruleset_parse(struct quark_ruleset *ruleset, FILE *in,
    char *err_buf, size_t err_buf_len)
{
	struct quark_parser_ctx	 ctx;
	size_t			 i;
	int			 quark_parse(struct quark_parser_ctx *);

	quark_ruleset_init(ruleset);
	bzero(&ctx, sizeof(ctx));
	ctx.in = in;
	ctx.ruleset = ruleset;

	quark_parse(&ctx);

	/* Free up parser arena */
	for (i = 0; i < ctx.n_allocs; i++)
		free(ctx.allocs[i]);
	free(ctx.allocs);
	free(ctx.strs);

	if (ctx.error) {
		quark_ruleset_clear(ctx.ruleset);
		if (err_buf != NULL)
			strlcpy(err_buf, ctx.errorbuf, err_buf_len);

		return (-1);
	}

	return (0);
}

static int
path_match(struct quark_rule_field *field, const char *a)
{
	struct quark_wild	*w = &field->wild;
	size_t			 alen;

	/*
	 * Include NUL in the comparison. Without it, "foo" would match "foobar"
	 * as a prefix. pre_len includes the NUL when it's an exact match. If
	 * post_len is 0, NUL is not included (hence zero), if post_len is
	 * positive, NUL is included.
	 */
	alen = strlen(a) + 1;	/* include NUL */

	if (w->pre_len + w->post_len > alen)
		return (0);
	if (memcmp(w->pre, a, w->pre_len) != 0)
		return (0);
	if (memcmp(w->post, a + alen - w->post_len, w->post_len) != 0)
		return (0);

	return (1);
}

/*
 * The event.scope of an event, one of QUARK_RULE_SCOPE_*. The values are
 * disjoint, "not a container" is { host unknown }:
 *   container	the cgroup of the process names a container
 *   host	the cgroup is known and does not name a container
 *   unknown	no process, no cgroup, or the container ID could not be
 *		stored (process_container_id() tries again next time)
 */
static int
event_scope(struct quark_event *qev)
{
	struct quark_process	*qp;

	qp = (struct quark_process *)qev->process;
	if (qp == NULL)
		return (QUARK_RULE_SCOPE_UNKNOWN);
	if (process_container_id(qp) != NULL)
		return (QUARK_RULE_SCOPE_CONTAINER);
	/* Parsed and not a container, a cleared cgroup resets the flag */
	if (qp->container_id_parsed)
		return (QUARK_RULE_SCOPE_HOST);

	return (QUARK_RULE_SCOPE_UNKNOWN);
}

/* 1 for match, 0 for non match */
static int
quark_rule_field_match(struct quark_rule *rule, struct quark_rule_field *field,
    struct quark_event *qev)
{
	const struct quark_process	*qp;

	qp = qev->process;

#define MATCH_PROC_FIELD(_p, _n, _v)					\
	((_p) != NULL && ((_p)->flags & QUARK_F_PROC) && (_p)->_n == (_v))

	switch (field->code) {
	case QUARK_RF_PID:
		if (qp != NULL)
			return (qp->pid == field->pid);
		break;
	case QUARK_RF_PPID:
		return (MATCH_PROC_FIELD(qp, proc_ppid, field->pid));
	case QUARK_RF_EXE:
		if (qp != NULL && qp->exe != NULL)
			return (path_match(field, qp->exe));
		break;
	case QUARK_RF_UID:
		return (MATCH_PROC_FIELD(qp, proc_uid, field->id));
	case QUARK_RF_GID:
		return (MATCH_PROC_FIELD(qp, proc_gid, field->id));
	case QUARK_RF_SID:
		return (MATCH_PROC_FIELD(qp, proc_sid, field->id));
		break;
	case QUARK_RF_COMM:
		if (qp != NULL)
			return (!strcmp(field->comm, qp->comm));
		break;
	case QUARK_RF_FILEPATH:
		if (qev->file != NULL)
			return (path_match(field, qev->file->path));
		break;
	case QUARK_RF_FILE_EXEC_CHANGE:
		if (qev->file != NULL)
			return (((qev->file->op_mask & QUARK_FILE_OP_CREATE) ||
			    (qev->file->change_mask & QUARK_FILE_CH_PERMS)) &&
			    (qev->file->mode & (S_IXUSR | S_IXGRP | S_IXOTH)));
		break;
	case QUARK_RF_POD_NAME:
		if (qp != NULL && qp->container != NULL &&
		    qp->container->pod != NULL &&
		    qp->container->pod->name != NULL)
			return (path_match(field, qp->container->pod->name));
		break;
	case QUARK_RF_CONTAINER_IMAGE:
		if (qp != NULL && qp->container != NULL &&
		    qp->container->image != NULL)
			return (path_match(field, qp->container->image));
		break;
	case QUARK_RF_EVENT_SCOPE:
		return (event_scope(qev) == (int)field->id);
	case QUARK_RF_POISON:
		if (qp != NULL)
			return (qp->poison_tag == field->poison_tag);
		break;
	default:
		break;
	}

#undef MATCH_PROC_FIELD

	return (0);
}

/* 1 when one of the values matches, the values of a field are ORed */
static int
cond_match(struct quark_rule *rule, struct quark_rule_cond *cond,
    struct quark_event *qev)
{
	size_t	i;

	for (i = 0; i < cond->n_values; i++) {
		if (quark_rule_field_match(rule, cond->values + i, qev))
			return (1);
	}

	return (0);
}

struct quark_rule *
quark_ruleset_match(struct quark_ruleset *ruleset, struct quark_event *qev)
{
	struct quark_rule	*rule;
	size_t			 i, j;
	struct quark_process	*qp;

	for (i = 0; i < ruleset->n_rules; i++) {
		rule = ruleset->rules + i;
		rule->evals++;
		for (j = 0; j < rule->n_conds; j++) {
			if (!cond_match(rule, rule->conds + j, qev))
				break;
		}
		/* All fields matched, this is the rule! */
		if (j == rule->n_conds) {
			rule->hits++;
			/* Poison rules continue to evaluate, others are done */
			if (rule->action != QUARK_RA_POISON)
				return (rule);
			/* Poison this process */
			qp = (struct quark_process *)qev->process;
			if (qp != NULL)
				qp->poison_tag = rule->poison_tag;
		}
	}

	return (NULL);
}

struct quark_rule *
quark_ruleset_append_rule(struct quark_ruleset *ruleset, int action, u64 poison_tag)
{
	struct quark_rule	*new_rules, *rule;
	size_t			 new_n_rules;

	if (action != QUARK_RA_DROP &&
	    action != QUARK_RA_PASS &&
	    action != QUARK_RA_POISON)
		return (errno = EINVAL, NULL);
	new_n_rules = ruleset->n_rules + 1;
	new_rules = reallocarray(ruleset->rules, new_n_rules,
	    sizeof(*ruleset->rules));
	if (new_rules == NULL)
		return (NULL);

	ruleset->rules = new_rules;
	ruleset->n_rules = new_n_rules;

	rule = &ruleset->rules[ruleset->n_rules - 1];
	rule->conds = NULL;
	rule->n_conds = 0;
	rule->action = action;
	rule->number = ruleset->n_rules - 1;
	rule->evals = 0;
	rule->hits = 0;
	if (action == QUARK_RA_POISON)
		rule->poison_tag = poison_tag;
	else
		rule->poison_tag = 0;

	return (rule);
}

/*
 * Initialize a wildcard from the user string in w->pre, which is copied.
 * As in foo*bar: pre = foo, post = bar. Only one * is allowed. On error
 * w->pre is left untouched and nothing is allocated. Returns -1 with
 * errno set.
 */
static int
wild_init(struct quark_wild *w)
{
	char	*copy, *star;
	size_t	 len;

	w->post = NULL;
	w->pre_len = w->post_len = 0;

	if (w->pre == NULL || (len = strlen(w->pre)) == 0 || len >= PATH_MAX)
		return (errno = EINVAL, -1);
	star = strchr(w->pre, '*');
	if (star != NULL && strchr(star + 1, '*') != NULL)
		return (errno = EINVAL, -1);
	if ((copy = strdup(w->pre)) == NULL)
		return (-1);
	/* Rebase star into the copy */
	if (star != NULL)
		star = copy + (star - w->pre);
	w->pre = copy;
	w->post = w->pre + len;
	if (star != NULL) {
		*star = 0;
		w->post = star + 1;
	}
	/* Don't move this up, as the block above might shorten "pre" */
	w->pre_len = strlen(w->pre);
	w->post_len = strlen(w->post);
	if (star == NULL)
		w->pre_len++; /* Include NUL in the comparison */
	if (w->post_len > 0)
		w->post_len++; /* Include NUL in the comparison */

	return (0);
}

/*
 * Check one value and prepare it for matching. A wildcard is copied, see
 * wild_init(). On error nothing is allocated. Returns -1 with errno set.
 */
static int
rule_field_validate(struct quark_rule_field *rf)
{
	switch (rf->code) {
	case QUARK_RF_PID:		/* FALLTHROUGH */
	case QUARK_RF_PPID:
		if (rf->pid == 0)
			return (errno = EINVAL, -1);
		break;
	case QUARK_RF_UID:		/* FALLTHROUGH */
	case QUARK_RF_GID:		/* FALLTHROUGH */
	case QUARK_RF_SID:
		break;
	case QUARK_RF_COMM:
		if (strlen(rf->comm) == 0)
			return (errno = EINVAL, -1);
		break;
	case QUARK_RF_EXE:		/* FALLTHROUGH */
	case QUARK_RF_FILEPATH:		/* FALLTHROUGH */
	case QUARK_RF_POD_NAME:		/* FALLTHROUGH */
	case QUARK_RF_CONTAINER_IMAGE:
		if (wild_init(&rf->wild) == -1)
			return (-1);
		break;
	case QUARK_RF_FILE_EXEC_CHANGE:
		break;
	case QUARK_RF_EVENT_SCOPE:
		switch (rf->id) {
		case QUARK_RULE_SCOPE_CONTAINER:	/* FALLTHROUGH */
		case QUARK_RULE_SCOPE_HOST:		/* FALLTHROUGH */
		case QUARK_RULE_SCOPE_UNKNOWN:
			break;
		default:
			return (errno = EINVAL, -1);
		}
		break;
	case QUARK_RF_POISON:
		if (rf->poison_tag == 0)
			return (errno = EINVAL, -1);
		break;
	default:
		return (errno = EINVAL, -1);
	}

	return (0);
}

/*
 * Add one field with a list of values to the rule. The field matches when
 * one of the values matches. Every value must have the same code. The
 * values are copied, a wildcard string is copied too. On error the rule
 * is unchanged. Returns -1 with errno set.
 */
int
quark_rule_match_field_list(struct quark_rule *rule,
    const struct quark_rule_field *rfs, size_t n)
{
	struct quark_rule_cond	*new_conds;
	struct quark_rule_field	*values;
	size_t			 i, j;
	int			 saved_errno;

	if (rfs == NULL || n == 0)
		return (errno = EINVAL, -1);
	for (i = 1; i < n; i++) {
		if (rfs[i].code != rfs[0].code)
			return (errno = EINVAL, -1);
	}
	if ((values = calloc(n, sizeof(*values))) == NULL)
		return (-1);
	for (i = 0; i < n; i++) {
		values[i] = rfs[i];
		if (rule_field_validate(&values[i]) == -1)
			goto bad;
	}

	new_conds = reallocarray(rule->conds, rule->n_conds + 1,
	    sizeof(*rule->conds));
	if (new_conds == NULL)
		goto bad;
	rule->conds = new_conds;
	rule->conds[rule->n_conds].code = rfs[0].code;
	rule->conds[rule->n_conds].values = values;
	rule->conds[rule->n_conds].n_values = n;
	rule->n_conds++;

	return (0);

bad:
	/* The values before values[i] are prepared, free them */
	saved_errno = errno;
	for (j = 0; j < i; j++)
		rule_field_free(&values[j]);
	free(values);
	errno = saved_errno;

	return (-1);
}

int
quark_rule_match_field(struct quark_rule *rule, struct quark_rule_field rf)
{
	return (quark_rule_match_field_list(rule, &rf, 1));
}
