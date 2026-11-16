// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024-2026 Elastic NV */

#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
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
	for (i = 0; i < ruleset->n_tags; i++)
		free(ruleset->tag_names[i]);
	quark_ruleset_init(ruleset);
}

int
quark_ruleset_parse(struct quark_ruleset *ruleset, FILE *in,
    char *err_buf, size_t err_buf_len)
{
	struct quark_parser_ctx	 ctx;
	size_t			 i;
	int			 quark_parse(struct quark_parser_ctx *);
	void			 quark_error(struct quark_parser_ctx *,
				     const char *, ...);

	quark_ruleset_init(ruleset);
	bzero(&ctx, sizeof(ctx));
	ctx.in = in;
	ctx.ruleset = ruleset;

	quark_parse(&ctx);
	/* The grammar closes every block, this guards the parser */
	if (!ctx.error && ruleset->block_open)
		quark_error(&ctx, "unterminated tag block");

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
 * disjoint, a value needs positive evidence, and "not a container" is
 * { host unknown }:
 *   container	the last cgroup component names a container
 *   host	the cgroup is in the systemd host layout, see cgroup_is_host()
 *   unknown	everything else: no process, no or empty cgroup, a relative
 *		path, a layout we don't recognize, a cgroup nested in a
 *		container, or the container ID could not be stored
 *		(process_container_id() tries again next time)
 */
static int
event_scope(struct quark_event *qev)
{
	struct quark_process	*qp;

	qp = (struct quark_process *)qev->process;
	if (qp == NULL || qp->cgroup == NULL || *qp->cgroup == 0)
		return (QUARK_RULE_SCOPE_UNKNOWN);
	if (process_container_id(qp) != NULL)
		return (QUARK_RULE_SCOPE_CONTAINER);
	/* Not parsed means the container ID could not be stored */
	if (qp->container_id_parsed && cgroup_is_host(qp->cgroup))
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

/* 1 when every condition matches, the conditions of a rule are ANDed */
static int
rule_match(struct quark_rule *rule, struct quark_event *qev)
{
	size_t	i;

	for (i = 0; i < rule->n_conds; i++) {
		if (!cond_match(rule, rule->conds + i, qev))
			return (0);
	}

	return (1);
}

/*
 * Evaluate the ruleset on an event, top to bottom. Set qev->tags and return
 * the first pass or drop rule that matches, or NULL. Poison rules and tag
 * blocks don't end the evaluation, all of them apply.
 *
 * A tag block sets its tag when no "except on" line matches and one "on"
 * line matches. The except lines come first, so the first match in a
 * block decides it: an except line leaves the block, an on line sets the
 * tag and leaves the block too, the rest can't add anything. A block whose
 * tag is already set is skipped, an except line is local to its block and
 * never removes a tag.
 *
 * The caller decides delivery: a drop removes only an event without tags.
 */
struct quark_rule *
quark_ruleset_match(struct quark_ruleset *ruleset, struct quark_event *qev)
{
	struct quark_rule	*rule;
	size_t			 i;
	struct quark_process	*qp;

	qev->tags = 0;
	qev->ruleset = ruleset;

	for (i = 0; i < ruleset->n_rules; i++) {
		rule = ruleset->rules + i;
		if ((rule->action == QUARK_RA_TAG ||
		    rule->action == QUARK_RA_EXCEPT) &&
		    (qev->tags & rule->tags) == rule->tags) {
			i = rule->skip_to - 1;
			continue;
		}
		rule->evals++;
		if (!rule_match(rule, qev))
			continue;
		rule->hits++;
		switch (rule->action) {
		case QUARK_RA_EXCEPT:
			i = rule->skip_to - 1;
			break;
		case QUARK_RA_TAG:
			qev->tags |= rule->tags;
			i = rule->skip_to - 1;
			break;
		case QUARK_RA_POISON:
			/* Poison this process */
			qp = (struct quark_process *)qev->process;
			if (qp != NULL)
				qp->poison_tag = rule->poison_tag;
			break;
		default:
			/* Pass and drop are done */
			return (rule);
		}
	}

	return (NULL);
}

/*
 * Append a rule. QUARK_RA_TAG and QUARK_RA_EXCEPT are the "on" and
 * "except on" lines of the open tag block, see quark_ruleset_tag_begin(),
 * the except lines come first. The other actions are outside of a block.
 * Returns NULL with errno set.
 */
struct quark_rule *
quark_ruleset_append_rule(struct quark_ruleset *ruleset, int action, u64 poison_tag)
{
	struct quark_rule	*new_rules, *rule;
	size_t			 new_n_rules;

	switch (action) {
	case QUARK_RA_DROP:		/* FALLTHROUGH */
	case QUARK_RA_PASS:		/* FALLTHROUGH */
	case QUARK_RA_POISON:
		if (ruleset->block_open)
			return (errno = EINVAL, NULL);
		break;
	case QUARK_RA_EXCEPT:
		if (!ruleset->block_open || ruleset->block_has_on)
			return (errno = EINVAL, NULL);
		break;
	case QUARK_RA_TAG:
		if (!ruleset->block_open)
			return (errno = EINVAL, NULL);
		break;
	default:
		return (errno = EINVAL, NULL);
	}
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
	rule->tags = 0;
	rule->skip_to = 0;
	if (action == QUARK_RA_POISON)
		rule->poison_tag = poison_tag;
	else
		rule->poison_tag = 0;
	if (action == QUARK_RA_TAG || action == QUARK_RA_EXCEPT)
		rule->tags = ruleset->block_tag;
	if (action == QUARK_RA_TAG)
		ruleset->block_has_on = 1;

	return (rule);
}

/* A tag name is [A-Za-z0-9_.-], 1 to QUARK_TAG_NAME_MAX bytes */
static int
tag_name_valid(const char *name)
{
	const char	*p;

	if (name == NULL || *name == 0 ||
	    strlen(name) > QUARK_TAG_NAME_MAX)
		return (0);
	for (p = name; *p != 0; p++) {
		if (!isalnum((unsigned char)*p) &&
		    *p != '_' && *p != '.' && *p != '-')
			return (0);
	}

	return (1);
}

/*
 * Open a tag block, the rules appended until quark_ruleset_tag_end() are
 * its lines. Blocks with the same name share one bit. The name blocked is
 * reserved for denied operations. Returns -1 with errno set: EINVAL for a
 * bad name or a block already open, E2BIG past QUARK_MAX_TAGS names.
 */
int
quark_ruleset_tag_begin(struct quark_ruleset *ruleset, const char *name)
{
	u_int	bit;

	if (ruleset->block_open || !tag_name_valid(name) ||
	    !strcmp(name, "blocked"))
		return (errno = EINVAL, -1);
	for (bit = 0; bit < ruleset->n_tags; bit++) {
		if (!strcmp(ruleset->tag_names[bit], name))
			break;
	}
	if (bit == ruleset->n_tags) {
		if (ruleset->n_tags == QUARK_MAX_TAGS)
			return (errno = E2BIG, -1);
		if ((ruleset->tag_names[bit] = strdup(name)) == NULL)
			return (-1);
		ruleset->n_tags++;
	}
	ruleset->block_open = 1;
	ruleset->block_has_on = 0;
	ruleset->block_start = ruleset->n_rules;
	ruleset->block_tag = 1ULL << bit;

	return (0);
}

/*
 * Close the open tag block. It needs an "on" line, and an "except on" line
 * needs a field, otherwise it matches every event and the block is dead.
 * Returns -1 with errno set to EINVAL.
 */
int
quark_ruleset_tag_end(struct quark_ruleset *ruleset)
{
	size_t	i;

	if (!ruleset->block_open || !ruleset->block_has_on)
		return (errno = EINVAL, -1);
	for (i = ruleset->block_start; i < ruleset->n_rules; i++) {
		if (ruleset->rules[i].action == QUARK_RA_EXCEPT &&
		    ruleset->rules[i].n_conds == 0)
			return (errno = EINVAL, -1);
	}
	for (i = ruleset->block_start; i < ruleset->n_rules; i++)
		ruleset->rules[i].skip_to = ruleset->n_rules;
	ruleset->block_open = 0;
	ruleset->block_has_on = 0;
	ruleset->block_tag = 0;

	return (0);
}

/* The name of a tag bit, or NULL */
const char *
quark_ruleset_tag_name(const struct quark_ruleset *ruleset, u_int bit)
{
	if (bit >= ruleset->n_tags)
		return (NULL);

	return (ruleset->tag_names[bit]);
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
