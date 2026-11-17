// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

/*
 * The "block" blocks of a ruleset, compiled for the kernel.
 *
 * A block denies an operation when no "except on" line and one "on" line
 * match it, see quark_ruleset_block_begin(). A hook can't loop over rules
 * and compare strings, so the blocks are turned inside out, as the policy
 * of Defend for Containers is: every distinct line of every block is one
 * bit, and each field maps a value to the set of lines that accept it.
 * The hook then makes one lookup per field, ANDs the sets into M, the
 * lines that match, and tests two masks per block:
 *
 *	deny when (on & M) != 0 && (except & M) == 0
 *
 * A line that does not use a field accepts any value of it, these are the
 * dc_ ("don't care") sets. A line that uses a field never matches when the
 * value is not available: an unknown value does not match, on an on line
 * and on an except line, as in a tag block.
 *
 * Nothing here talks to the kernel. quark_block_eval() applies the compiled
 * form as a hook does, and quark_block_eval_rules() walks the rules with
 * the matching code of the tag blocks, so that the two can be compared.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quark.h"

#define BLOCK_CONTAINER_FIELDS	(QUARK_RF_POD_NAME | QUARK_RF_CONTAINER_IMAGE)

static int
is_block_line(const struct quark_rule *rule)
{
	return (rule->action == QUARK_RA_BLOCK_ON ||
	    rule->action == QUARK_RA_BLOCK_EXCEPT);
}

/* The fields that a line uses, QUARK_RF_* */
static u64
line_fields(const struct quark_rule *rule)
{
	u64	fields;
	size_t	i;

	for (fields = 0, i = 0; i < rule->n_conds; i++)
		fields |= rule->conds[i].code;

	return (fields);
}

/*
 * A growing string
 */
struct sbuf {
	char	*buf;
	size_t	 len;
	size_t	 cap;
};

static int
sbuf_add(struct sbuf *sb, const char *s, size_t len)
{
	char	*new_buf;
	size_t	 new_cap;

	if (sb->len + len + 1 > sb->cap) {
		new_cap = (sb->len + len + 1) * 2;
		if ((new_buf = realloc(sb->buf, new_cap)) == NULL)
			return (-1);
		sb->buf = new_buf;
		sb->cap = new_cap;
	}
	memcpy(sb->buf + sb->len, s, len);
	sb->len += len;
	sb->buf[sb->len] = 0;

	return (0);
}

/* The pattern as the user wrote it, pre*post. NULL with errno set. */
static char *
wild_text(const struct quark_wild *w)
{
	char	*text;
	int	 star;

	/* An exact match includes the NUL in pre_len, see wild_init() */
	star = w->pre_len == strlen(w->pre);
	if (asprintf(&text, "%s%s%s", w->pre, star ? "*" : "", w->post) == -1)
		return (NULL);

	return (text);
}

static int
text_cmp(const void *a, const void *b)
{
	return (strcmp(*(char * const *)a, *(char * const *)b));
}

/* Add "<code>(<len>:<value>...)" with the values sorted and unique */
static int
signature_add_cond(struct sbuf *sb, const struct quark_rule_cond *cond)
{
	char	**texts, tmp[64];
	size_t	  i;
	int	  r;

	r = -1;
	if ((texts = calloc(cond->n_values, sizeof(*texts))) == NULL)
		return (-1);
	for (i = 0; i < cond->n_values; i++) {
		if ((texts[i] = wild_text(&cond->values[i].wild)) == NULL)
			goto done;
	}
	qsort(texts, cond->n_values, sizeof(*texts), text_cmp);

	snprintf(tmp, sizeof(tmp), "%llx(", (unsigned long long)cond->code);
	if (sbuf_add(sb, tmp, strlen(tmp)) == -1)
		goto done;
	for (i = 0; i < cond->n_values; i++) {
		if (i > 0 && !strcmp(texts[i], texts[i - 1]))
			continue;
		/* The length makes a value with any byte unambiguous */
		snprintf(tmp, sizeof(tmp), "%zu:", strlen(texts[i]));
		if (sbuf_add(sb, tmp, strlen(tmp)) == -1 ||
		    sbuf_add(sb, texts[i], strlen(texts[i])) == -1)
			goto done;
	}
	if (sbuf_add(sb, ")", 1) == -1)
		goto done;
	r = 0;
done:
	for (i = 0; i < cond->n_values; i++)
		free(texts[i]);
	free(texts);

	return (r);
}

/*
 * A string that is equal for two lines that match the same operations:
 * the fields in the order of their code, each with its values sorted and
 * unique. The order of the fields in a line and of the values in a list
 * makes no difference. NULL with errno set.
 */
static char *
line_signature(const struct quark_rule *rule)
{
	struct sbuf			 sb;
	const struct quark_rule_cond	*cond, *next;
	u64				 last;
	size_t				 i, n;

	bzero(&sb, sizeof(sb));
	if (sbuf_add(&sb, "", 0) == -1)
		return (NULL);
	/* A line has a few fields, pick the next lowest code each time */
	for (last = 0, n = 0; n < rule->n_conds; n++) {
		for (next = NULL, i = 0; i < rule->n_conds; i++) {
			cond = rule->conds + i;
			if (cond->code > last &&
			    (next == NULL || cond->code < next->code))
				next = cond;
		}
		/* No field repeats, quark_ruleset_block_check_line() */
		if (next == NULL)
			break;
		if (signature_add_cond(&sb, next) == -1) {
			free(sb.buf);
			return (NULL);
		}
		last = next->code;
	}

	return (sb.buf);
}

/*
 * Order by bytes, a prefix sorts before what it is a prefix of
 */
static int
block_path_cmp(const void *va, const void *vb)
{
	const struct quark_block_path	*a = va, *b = vb;
	int				 r;

	r = memcmp(a->path, b->path, MIN(a->len, b->len));
	if (r != 0)
		return (r);
	if (a->len != b->len)
		return (a->len < b->len ? -1 : 1);

	return (0);
}

/*
 * Add the pattern of one value to a path list, or its line to the pattern
 * if we have it already.
 *	"/usr/bin/" then *	the bytes "/usr/bin/", a prefix
 *	"/usr/bin/curl"		the bytes "/usr/bin/curl" and the NUL, so
 *				that it is not a prefix of /usr/bin/curly
 *	a * alone		no bytes, a prefix of every path
 * These are pre and pre_len of the wildcard, see wild_init().
 */
static int
block_path_add(struct quark_block_path **paths, size_t *n_paths,
    const struct quark_wild *w, u64 bit)
{
	struct quark_block_path	*bp, *new_paths;
	size_t			 i;
	int			 exact;

	exact = w->pre_len == strlen(w->pre) + 1;
	for (i = 0; i < *n_paths; i++) {
		bp = *paths + i;
		if (bp->len == w->pre_len && bp->exact == exact &&
		    !memcmp(bp->path, w->pre, bp->len)) {
			bp->own |= bit;
			return (0);
		}
	}

	new_paths = reallocarray(*paths, *n_paths + 1, sizeof(**paths));
	if (new_paths == NULL)
		return (-1);
	*paths = new_paths;
	bp = *paths + *n_paths;
	bzero(bp, sizeof(*bp));
	/* pre has at least its NUL, so there is always a byte to copy */
	if ((bp->path = malloc(w->pre_len + 1)) == NULL)
		return (-1);
	memcpy(bp->path, w->pre, w->pre_len);
	bp->path[w->pre_len] = 0;
	bp->len = w->pre_len;
	bp->exact = exact;
	bp->own = bit;
	(*n_paths)++;

	return (0);
}

/*
 * A longest prefix lookup finds one pattern only, the longest that
 * matches. Every shorter prefix pattern matches the same path too, so each
 * pattern also carries the lines of the prefix patterns that are a prefix
 * of it. One lookup then gives all the lines that accept the path.
 */
static void
block_paths_close(struct quark_block_path *paths, size_t n_paths)
{
	struct quark_block_path	*bp, *pre;
	size_t			 i, j;

	if (n_paths == 0)
		return;
	qsort(paths, n_paths, sizeof(*paths), block_path_cmp);
	for (i = 0; i < n_paths; i++) {
		bp = paths + i;
		bp->lines = bp->own;
		for (j = 0; j < n_paths; j++) {
			pre = paths + j;
			if (pre->exact || pre->len > bp->len ||
			    memcmp(pre->path, bp->path, pre->len))
				continue;
			bp->lines |= pre->own;
		}
	}
}

/*
 * The lines that accept this path: those of the longest pattern that
 * matches it, as a longest prefix lookup in the kernel does. 0 if no
 * pattern matches.
 */
u64
quark_block_path_bits(const struct quark_block_path *paths, size_t n_paths,
    const char *path)
{
	const struct quark_block_path	*bp, *best;
	size_t				 i, len;

	len = strlen(path) + 1;		/* an exact pattern compares the NUL */
	for (best = NULL, i = 0; i < n_paths; i++) {
		bp = paths + i;
		if (bp->len > len || memcmp(bp->path, path, bp->len))
			continue;
		if (best == NULL || bp->len > best->len)
			best = bp;
	}

	return (best == NULL ? 0 : best->lines);
}

/*
 * The bit of a line, a new one unless an equal line has one already.
 * -1 with errno set, E2BIG past NOVA_BLOCK_LINES lines.
 */
static int
line_bit(struct quark_block_prog *prog, char **sigs,
    const struct quark_rule *rule)
{
	char	*sig;
	u_int	 bit;

	if ((sig = line_signature(rule)) == NULL)
		return (-1);
	for (bit = 0; bit < prog->n_lines; bit++) {
		if (!strcmp(sigs[bit], sig)) {
			free(sig);
			return (bit);
		}
	}
	if (prog->n_lines == NOVA_BLOCK_LINES) {
		free(sig);
		return (errno = E2BIG, -1);
	}
	sigs[bit] = sig;
	prog->line_rule[bit] = rule->number;
	prog->n_lines++;

	return (bit);
}

void
quark_block_free(struct quark_block_prog *prog)
{
	size_t	i;

	if (prog == NULL)
		return;
	for (i = 0; i < prog->n_exe; i++)
		free(prog->exe[i].path);
	free(prog->exe);
	for (i = 0; i < prog->n_file; i++)
		free(prog->file[i].path);
	free(prog->file);
	free(prog);
}

/*
 * Compile the blocks of a ruleset. The result borrows the ruleset, which
 * must not change or go away before quark_block_free(). A ruleset without
 * blocks gives an empty result. Returns NULL with errno set: EINVAL for a
 * ruleset with an open block or a line that
 * quark_ruleset_block_check_line() refuses, E2BIG past NOVA_MAX_BLOCKS
 * blocks or NOVA_BLOCK_LINES distinct lines.
 */
struct quark_block_prog *
quark_block_compile(const struct quark_ruleset *ruleset)
{
	struct quark_block_prog		*prog;
	struct nova_block		*blk;
	const struct quark_rule		*rule, *line;
	const struct quark_rule_cond	*cond;
	char				*sigs[NOVA_BLOCK_LINES];
	u64				 fields, bit;
	size_t				 i, j, k, end;
	int				 b, saved_errno;

	bzero(sigs, sizeof(sigs));
	if (ruleset->block_open)
		return (errno = EINVAL, NULL);
	if ((prog = calloc(1, sizeof(*prog))) == NULL)
		return (NULL);
	prog->ruleset = ruleset;

	/* The lines of each block as bits */
	for (i = 0; i < ruleset->n_rules; i = end) {
		rule = ruleset->rules + i;
		if (!is_block_line(rule)) {
			end = i + 1;
			continue;
		}
		end = rule->skip_to;
		if (end <= i || end > ruleset->n_rules) {
			errno = EINVAL;
			goto fail;
		}
		if (prog->n_blocks == NOVA_MAX_BLOCKS) {
			errno = E2BIG;
			goto fail;
		}
		blk = &prog->blocks[prog->n_blocks++];
		for (j = i; j < end; j++) {
			line = ruleset->rules + j;
			if (!is_block_line(line) ||
			    quark_ruleset_block_check_line(ruleset,
			    line) != NULL) {
				errno = EINVAL;
				goto fail;
			}
			if ((b = line_bit(prog, sigs, line)) == -1)
				goto fail;
			if (line->action == QUARK_RA_BLOCK_ON)
				blk->on |= 1ULL << b;
			else
				blk->except |= 1ULL << b;
		}
	}

	/* What each line needs from each field */
	for (i = 0; i < prog->n_lines; i++) {
		line = ruleset->rules + prog->line_rule[i];
		bit = 1ULL << i;
		fields = line_fields(line);
		if (!(fields & QUARK_RF_EXE))
			prog->dc_exe |= bit;
		if (!(fields & QUARK_RF_FILEPATH))
			prog->dc_file |= bit;
		if (!(fields & BLOCK_CONTAINER_FIELDS))
			prog->dc_container |= bit;
		for (j = 0; j < line->n_conds; j++) {
			cond = line->conds + j;
			for (k = 0; k < cond->n_values; k++) {
				if (cond->code == QUARK_RF_EXE &&
				    block_path_add(&prog->exe, &prog->n_exe,
				    &cond->values[k].wild, bit) == -1)
					goto fail;
				if (cond->code == QUARK_RF_FILEPATH &&
				    block_path_add(&prog->file, &prog->n_file,
				    &cond->values[k].wild, bit) == -1)
					goto fail;
			}
		}
	}
	block_paths_close(prog->exe, prog->n_exe);
	block_paths_close(prog->file, prog->n_file);

	for (i = 0; i < NOVA_BLOCK_LINES; i++)
		free(sigs[i]);

	return (prog);

fail:
	saved_errno = errno;
	for (i = 0; i < NOVA_BLOCK_LINES; i++)
		free(sigs[i]);
	quark_block_free(prog);
	errno = saved_errno;

	return (NULL);
}

/*
 * The lines whose container fields, pod.name and container.image, all
 * match this container, and the lines that have none. This is the value
 * the kernel keeps per container. NULL is a container without metadata:
 * only the lines without container fields.
 */
u64
quark_block_container_bits(const struct quark_block_prog *prog,
    const struct quark_container *container)
{
	const struct quark_rule		*line;
	const struct quark_rule_cond	*cond;
	u64				 bits;
	size_t				 i, j;

	bits = prog->dc_container;
	if (container == NULL)
		return (bits);
	for (i = 0; i < prog->n_lines; i++) {
		if (bits & (1ULL << i))
			continue;
		line = prog->ruleset->rules + prog->line_rule[i];
		for (j = 0; j < line->n_conds; j++) {
			cond = line->conds + j;
			if ((cond->code & BLOCK_CONTAINER_FIELDS) &&
			    !quark_rule_cond_match_container(cond, container))
				break;
		}
		if (j == line->n_conds)
			bits |= 1ULL << i;
	}

	return (bits);
}

/*
 * The path of an operation as a hook can use it. A path that does not fit
 * in a lookup key is not available, as one that could not be resolved.
 */
static const char *
input_path(const struct quark_block_input *in)
{
	if (in->path == NULL || strlen(in->path) >= NOVA_PATHLEN)
		return (NULL);

	return (in->path);
}

/*
 * Apply the compiled blocks to an operation of a process in a container,
 * with the steps of a hook. Returns the number of the first block that
 * denies it, starting from 0, or -1.
 */
int
quark_block_eval(const struct quark_block_prog *prog,
    const struct quark_block_input *in)
{
	const char	*path;
	u64		 m;
	u_int		 b;

	m = quark_block_container_bits(prog, in->container);
	path = input_path(in);
	if (in->kind == QUARK_BLOCK_PROCESS) {
		if (path != NULL)
			m &= quark_block_path_bits(prog->exe, prog->n_exe,
			    path) | prog->dc_exe;
		else
			m &= prog->dc_exe;
		/* No file here, a line with file.path does not match */
		m &= prog->dc_file;
	} else {
		if (path != NULL)
			m &= quark_block_path_bits(prog->file, prog->n_file,
			    path) | prog->dc_file;
		else
			m &= prog->dc_file;
		/* The file hooks don't read the executable */
		m &= prog->dc_exe;
	}

	for (b = 0; b < prog->n_blocks; b++) {
		if ((prog->blocks[b].on & m) != 0 &&
		    (prog->blocks[b].except & m) == 0)
			return (b);
	}

	return (-1);
}

/*
 * The reference for quark_block_eval(): the same question answered from
 * the rules, with the matching code of the tag blocks and nothing of the
 * compiled form. In each block, the first line that matches decides: an
 * except line leaves the block, an on line denies. Returns the number of
 * the first block that denies, starting from 0, or -1.
 */
int
quark_block_eval_rules(const struct quark_ruleset *ruleset,
    const struct quark_block_input *in)
{
	struct quark_event	 qev;
	struct quark_process	 qp;
	struct quark_file	 file;
	const struct quark_rule	*rule, *line;
	const char		*path;
	size_t			 i, j, end;
	int			 b;

	/* The operation as an event that a rule can match */
	bzero(&qev, sizeof(qev));
	bzero(&qp, sizeof(qp));
	bzero(&file, sizeof(file));
	qev.process = &qp;
	qp.container = (struct quark_container *)in->container;
	path = input_path(in);
	if (in->kind == QUARK_BLOCK_PROCESS)
		qp.exe = (char *)path;
	else if (path != NULL) {
		file.path = path;
		qev.file = &file;
	}

	for (i = 0, b = 0; i < ruleset->n_rules; i = end) {
		rule = ruleset->rules + i;
		if (!is_block_line(rule)) {
			end = i + 1;
			continue;
		}
		end = rule->skip_to;
		if (end <= i || end > ruleset->n_rules)
			return (-1);
		for (j = i; j < end; j++) {
			line = ruleset->rules + j;
			if (!quark_rule_match(line, &qev))
				continue;
			if (line->action == QUARK_RA_BLOCK_ON)
				return (b);
			break;
		}
		b++;
	}

	return (-1);
}
