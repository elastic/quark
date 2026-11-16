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

void
quark_ruleset_clear(struct quark_ruleset *ruleset)
{
	struct quark_rule	*rule;
	size_t			 i, j;

	for (i = 0; i < ruleset->n_rules; i++) {
		rule = ruleset->rules + i;
		for (j = 0; j < rule->n_fields; j++) {
			switch (rule->fields[j].code) {
			case QUARK_RF_FILEPATH:		/* FALLTHROUGH */
			case QUARK_RF_EXE:		/* FALLTHROUGH */
			case QUARK_RF_POD_NAME:		/* FALLTHROUGH */
			case QUARK_RF_CONTAINER_IMAGE:
				free(rule->fields[j].wild.pre);
				break;
			default:
				break;
			}
		}
		free(rule->fields);
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
		/* An unknown cgroup is not a container. */
		if (qp != NULL && field->id == QUARK_RULE_SCOPE_CONTAINER)
			return (process_container_id(
			    (struct quark_process *)qp) != NULL);
		break;
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

struct quark_rule *
quark_ruleset_match(struct quark_ruleset *ruleset, struct quark_event *qev)
{
	struct quark_rule	*rule;
	struct quark_rule_field		*field;
	size_t			 i, j;
	struct quark_process	*qp;

	for (i = 0; i < ruleset->n_rules; i++) {
		rule = ruleset->rules + i;
		rule->evals++;
		for (j = 0; j < rule->n_fields; j++) {
			field = rule->fields + j;
			if (!quark_rule_field_match(rule, field, qev))
				break;
		}
		/* All fields matched, this is the rule! */
		if (j == rule->n_fields) {
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
	rule->fields = NULL;
	rule->n_fields = 0;
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

int
quark_rule_match_field(struct quark_rule *rule, struct quark_rule_field rf)
{
	struct quark_rule_field	*new_fields;
	size_t			 new_n_fields;
	char			*path;

	path = NULL;

	switch (rf.code) {
	case QUARK_RF_PID:		/* FALLTHROUGH */
	case QUARK_RF_PPID:
		if (rf.pid == 0)
			goto inval;
		break;
	case QUARK_RF_UID:		/* FALLTHROUGH */
	case QUARK_RF_GID:		/* FALLTHROUGH */
	case QUARK_RF_SID:
		break;
	case QUARK_RF_COMM:
		if (strlen(rf.comm) == 0)
			goto inval;
		break;
	case QUARK_RF_EXE:		/* FALLTHROUGH */
	case QUARK_RF_FILEPATH:		/* FALLTHROUGH */
	case QUARK_RF_POD_NAME:		/* FALLTHROUGH */
	case QUARK_RF_CONTAINER_IMAGE:
		if (wild_init(&rf.wild) == -1)
			goto bad;
		path = rf.wild.pre;
		break;
	case QUARK_RF_FILE_EXEC_CHANGE:
		break;
	case QUARK_RF_EVENT_SCOPE:
		if (rf.id != QUARK_RULE_SCOPE_CONTAINER)
			goto inval;
		break;
	case QUARK_RF_POISON:
		if (rf.poison_tag == 0)
			goto inval;
		break;
	default:
		goto inval;
	}

	new_n_fields = rule->n_fields + 1;
	new_fields = reallocarray(rule->fields, new_n_fields,
	    sizeof(*rule->fields));
	if (new_fields == NULL)
		goto bad;

	rule->fields = new_fields;
	rule->n_fields = new_n_fields;
	rule->fields[rule->n_fields - 1] = rf;

	return (0);

inval:
	errno = EINVAL;
bad:
	free(path);

	return (-1);
}
