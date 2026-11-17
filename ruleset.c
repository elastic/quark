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
		quark_error(&ctx, "unterminated block");

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
	/* QUARK_RF_EVENT_SCOPE is matched in cond_match(), once per list */
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
	int	scope;

	/*
	 * The scope walks the cgroup, compute it once for the whole list, as
	 * in "drop on event.scope { host unknown }" which sees every event.
	 */
	if (cond->code == QUARK_RF_EVENT_SCOPE) {
		scope = event_scope(qev);
		for (i = 0; i < cond->n_values; i++) {
			if ((int)cond->values[i].id == scope)
				return (1);
		}
		return (0);
	}

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
 *
 * The lines of a "block" block are skipped, see quark_ruleset_block_begin().
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
		/* A block is enforced in the kernel, never evaluated here */
		if (rule->action == QUARK_RA_BLOCK_ON ||
		    rule->action == QUARK_RA_BLOCK_EXCEPT) {
			i = rule->skip_to - 1;
			continue;
		}
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
 * "except on" lines of the open tag block, see quark_ruleset_tag_begin().
 * QUARK_RA_BLOCK_ON and QUARK_RA_BLOCK_EXCEPT are the lines of the open
 * "block" block, see quark_ruleset_block_begin(). The except lines come
 * first. The other actions are outside of a block. Returns NULL with errno
 * set.
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
		if (!ruleset->block_open || ruleset->block_deny ||
		    ruleset->block_has_on)
			return (errno = EINVAL, NULL);
		break;
	case QUARK_RA_TAG:
		if (!ruleset->block_open || ruleset->block_deny)
			return (errno = EINVAL, NULL);
		break;
	case QUARK_RA_BLOCK_EXCEPT:
		if (!ruleset->block_open || !ruleset->block_deny ||
		    ruleset->block_has_on)
			return (errno = EINVAL, NULL);
		break;
	case QUARK_RA_BLOCK_ON:
		if (!ruleset->block_open || !ruleset->block_deny)
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
	/*
	 * Past this rule until quark_ruleset_tag_end() sets the end of the
	 * block, so that a match on an open block can't loop.
	 */
	rule->skip_to = ruleset->n_rules;
	if (action == QUARK_RA_POISON)
		rule->poison_tag = poison_tag;
	else
		rule->poison_tag = 0;
	if (action == QUARK_RA_TAG || action == QUARK_RA_EXCEPT)
		rule->tags = ruleset->block_tag;
	if (action == QUARK_RA_TAG || action == QUARK_RA_BLOCK_ON)
		ruleset->block_has_on = 1;

	return (rule);
}

/*
 * The tag names of the first version, the actions of a D4C response. The
 * engine takes up to QUARK_MAX_TAGS names, more can be allowed later.
 */
static const char *tags_allowed[] = { "log", "alert" };

static int
tag_name_valid(const char *name)
{
	size_t	i;

	if (name == NULL)
		return (0);
	for (i = 0; i < nitems(tags_allowed); i++) {
		if (!strcmp(name, tags_allowed[i]))
			return (1);
	}

	return (0);
}

/*
 * Open a tag block, the rules appended until quark_ruleset_tag_end() are
 * its lines. Blocks with the same name share one bit, the bits follow the
 * order of first use. The name is log or alert. Returns -1 with errno set:
 * EINVAL for another name or a block already open, E2BIG past
 * QUARK_MAX_TAGS names.
 */
int
quark_ruleset_tag_begin(struct quark_ruleset *ruleset, const char *name)
{
	u_int	bit;

	if (ruleset->block_open || !tag_name_valid(name))
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
	ruleset->block_deny = 0;
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

	if (!ruleset->block_open || ruleset->block_deny ||
	    !ruleset->block_has_on)
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

/* The tag of a denied attempt, a tag block can't set it */
#define QUARK_TAG_BLOCKED	"blocked"

/*
 * Open a "block" block, the rules appended until quark_ruleset_block_end()
 * are its lines, QUARK_RA_BLOCK_EXCEPT then QUARK_RA_BLOCK_ON. A block
 * denies an operation in the kernel when no except line and one on line
 * match. Userspace never evaluates its lines, quark_ruleset_match() skips
 * them. The first block registers the tag name blocked. Returns -1 with
 * errno set: EINVAL for a block already open, E2BIG past QUARK_MAX_TAGS
 * names.
 */
int
quark_ruleset_block_begin(struct quark_ruleset *ruleset)
{
	u_int	bit;

	if (ruleset->block_open)
		return (errno = EINVAL, -1);
	if (ruleset->blocked_tag == 0) {
		bit = ruleset->n_tags;
		if (bit == QUARK_MAX_TAGS)
			return (errno = E2BIG, -1);
		ruleset->tag_names[bit] = strdup(QUARK_TAG_BLOCKED);
		if (ruleset->tag_names[bit] == NULL)
			return (-1);
		ruleset->n_tags++;
		ruleset->blocked_tag = 1ULL << bit;
	}
	ruleset->block_open = 1;
	ruleset->block_deny = 1;
	ruleset->block_has_on = 0;
	ruleset->block_start = ruleset->n_rules;
	ruleset->block_tag = 0;

	return (0);
}

/* The path fields of a line of a block, process.exe and file.path */
static u64
block_line_paths(const struct quark_rule *rule)
{
	u64	paths;
	size_t	i;

	for (paths = 0, i = 0; i < rule->n_conds; i++)
		paths |= rule->conds[i].code &
		    (QUARK_RF_EXE | QUARK_RF_FILEPATH);

	return (paths);
}

/*
 * Check a line of a "block" block, with all its fields added. Returns NULL
 * when the line is valid, or why it is not. quark_ruleset_block_end()
 * checks every line, the parser calls this for the message.
 *
 * A block is evaluated in an LSM hook with a fixed number of lookups, and
 * it must mean what a D4C response means, so a line is narrower than a
 * line of a tag block:
 *  - The fields are process.exe, file.path, pod.name and container.image.
 *  - A path is fixed or ends in *, and fits in NOVA_PATHLEN.
 *  - A field appears once.
 *  - An on line has process.exe or file.path, which says what it denies:
 *    fork and exec, or the file operations. With container fields only
 *    it would deny everything in the container.
 *  - A block is about processes or about files: all its lines that have
 *    a path field have the same one.
 */
const char *
quark_ruleset_block_check_line(const struct quark_ruleset *ruleset,
    const struct quark_rule *rule)
{
	const struct quark_rule_cond	*cond;
	const struct quark_wild		*w;
	const struct quark_rule		*other;
	u64				 seen, paths, other_paths;
	size_t				 i, j, start;

	if (rule->action != QUARK_RA_BLOCK_ON &&
	    rule->action != QUARK_RA_BLOCK_EXCEPT)
		return ("not a line of a block");

	for (seen = 0, i = 0; i < rule->n_conds; i++) {
		cond = rule->conds + i;
		switch (cond->code) {
		case QUARK_RF_EXE:		/* FALLTHROUGH */
		case QUARK_RF_FILEPATH:
			for (j = 0; j < cond->n_values; j++) {
				w = &cond->values[j].wild;
				if (w->post_len != 0)
					return ("a path in a block takes * "
					    "only at the end");
				if (strlen(w->pre) >= NOVA_PATHLEN)
					return ("path too long in a block");
			}
			break;
		case QUARK_RF_POD_NAME:		/* FALLTHROUGH */
		case QUARK_RF_CONTAINER_IMAGE:
			break;
		default:
			return ("a block supports only process.exe, file.path, "
			    "pod.name and container.image");
		}
		if (seen & cond->code)
			return ("a field can't be repeated in a line of a "
			    "block");
		seen |= cond->code;
	}

	paths = seen & (QUARK_RF_EXE | QUARK_RF_FILEPATH);
	if (rule->action == QUARK_RA_BLOCK_EXCEPT && rule->n_conds == 0)
		return ("an except line needs a field");
	if (rule->action == QUARK_RA_BLOCK_ON && paths == 0)
		return ("an on line of a block needs process.exe or "
		    "file.path");
	if (paths == (QUARK_RF_EXE | QUARK_RF_FILEPATH))
		return ("a line of a block takes process.exe or file.path, "
		    "not both");

	/*
	 * The lines of this block before this one. A closed block shares
	 * one skip_to, an open block starts at block_start.
	 */
	if (ruleset->block_open && ruleset->block_deny &&
	    rule->number >= ruleset->block_start)
		start = ruleset->block_start;
	else {
		for (start = rule->number; start > 0; start--) {
			other = ruleset->rules + start - 1;
			if ((other->action != QUARK_RA_BLOCK_ON &&
			    other->action != QUARK_RA_BLOCK_EXCEPT) ||
			    other->skip_to != rule->skip_to)
				break;
		}
	}
	for (i = start; paths != 0 && i < rule->number; i++) {
		other_paths = block_line_paths(ruleset->rules + i);
		if (other_paths != 0 && other_paths != paths)
			return ("a block uses process.exe or file.path in its "
			    "lines, not both");
	}

	return (NULL);
}

/*
 * Close the open "block" block. It needs an "on" line, and every line
 * must pass quark_ruleset_block_check_line(). Returns -1 with errno set
 * to EINVAL.
 */
int
quark_ruleset_block_end(struct quark_ruleset *ruleset)
{
	size_t	i;

	if (!ruleset->block_open || !ruleset->block_deny ||
	    !ruleset->block_has_on)
		return (errno = EINVAL, -1);
	for (i = ruleset->block_start; i < ruleset->n_rules; i++) {
		if (quark_ruleset_block_check_line(ruleset,
		    ruleset->rules + i) != NULL)
			return (errno = EINVAL, -1);
	}
	for (i = ruleset->block_start; i < ruleset->n_rules; i++)
		ruleset->rules[i].skip_to = ruleset->n_rules;
	ruleset->block_open = 0;
	ruleset->block_deny = 0;
	ruleset->block_has_on = 0;
	ruleset->n_blocks++;

	return (0);
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
