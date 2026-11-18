// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

%{

#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "quark.h"

typedef struct {
	union {
		struct {
			int code;
			u64 poison_tag;
		} action;
		struct {
			u64			num_u64;
			struct quark_rule_field rf;
		};
		const char	*str;
	};
} quark_yystype;
#define QUARK_STYPE quark_yystype

void	quark_error(struct quark_parser_ctx *, const char *fmt, ...);
int	quark_lex(YYSTYPE *, struct quark_parser_ctx *);
static int	push_value(struct quark_parser_ctx *, const char *);
static int	add_values(struct quark_parser_ctx *, u64);
static int	line_begin(struct quark_parser_ctx *, int);
static int	line_end(struct quark_parser_ctx *);

#define ABORT(_fmt, ...) do {			\
	yyerror(ctx, _fmt, ##__VA_ARGS__);	\
	YYABORT;				\
} while (0)

%}

%expect 0
%define api.pure
%define api.prefix {quark_}
%define parse.error verbose
%parse-param {struct quark_parser_ctx *ctx}
%lex-param {struct quark_parser_ctx *ctx}
%initial-action {
	bzero(&$$, sizeof($$));
}

%token PASS DROP POISON ON ANY STRING TAG EXCEPT BLOCK
%token PROCESS_PID PROCESS_PPID PROCESS_UID PROCESS_GID PROCESS_SID
%token PROCESS_EXE FILE_PATH FILE_EXEC_CHANGE EVENT_SCOPE
%token POD_NAME CONTAINER_IMAGE

%%
grammar:	/* empty  */
		| grammar '\n'
		| grammar rule '\n'
		| grammar tagblock '\n'
		| grammar denyblock '\n'
		| error { YYABORT; }
		;

rule:		action {
			ctx->cur_rule = quark_ruleset_append_rule(ctx->ruleset,
			    $1.action.code, $1.action.poison_tag);
			if (ctx->cur_rule == NULL)
				ABORT("can't add rule: %s", strerror(errno));
		} ON matchbody {
			ctx->cur_rule = NULL;
		} ;

/*
 * tag <name> {
 *	except on <fields>
 *	on <fields>|any
 * }
 * One line each, the except lines first, see quark_ruleset_match().
 */
tagblock:	TAG STRING '{' {
			if (quark_ruleset_tag_begin(ctx->ruleset, $2.str) == -1) {
				if (errno == E2BIG)
					ABORT("too many tags, max %d",
					    QUARK_MAX_TAGS);
				ABORT("bad tag name: %s, only log and alert "
				    "are supported", $2.str);
			}
		} blocklines '}' {
			if (quark_ruleset_tag_end(ctx->ruleset) == -1)
				ABORT("tag block without an on line");
		} ;

/*
 * block {
 *	except on <fields>
 *	on <fields>
 * }
 * The lines of a tag block, with the fields that a block can enforce, see
 * quark_ruleset_block_check_line().
 */
denyblock:	BLOCK '{' {
			if (quark_ruleset_block_begin(ctx->ruleset) == -1)
				ABORT("can't open block: %s", strerror(errno));
		} blocklines '}' {
			if (quark_ruleset_block_end(ctx->ruleset) == -1)
				ABORT("block without an on line");
		} ;

/* The lines of a tag block or of a block */
blocklines:	/* empty */
		| blocklines '\n'
		| blocklines blockline '\n'
		;

blockline:	EXCEPT ON {
			if (line_begin(ctx, 1) == -1)
				ABORT("except on must come before on");
		} matchlist {
			if (line_end(ctx) == -1)
				YYABORT;
		} | ON {
			if (line_begin(ctx, 0) == -1)
				ABORT("can't add rule: %s", strerror(errno));
		} matchbody {
			if (line_end(ctx) == -1)
				YYABORT;
		} ;

action:		PASS {
			$$.action.code = QUARK_RA_PASS;
			$$.action.poison_tag = 0;
		} | DROP {
			$$.action.code = QUARK_RA_DROP;
			$$.action.poison_tag = 0;
		} | POISON num_u64 {
			$$.action.code = QUARK_RA_POISON;
			$$.action.poison_tag = $2.num_u64;
		} ;


matchbody:	matchlist
		| ANY
		;

matchlist:	match
		| matchlist match
		;

match:		FILE_EXEC_CHANGE {
			struct quark_rule_field rf;

			if (ctx->cur_rule == NULL)
				ABORT("parser bug, cur_rule is NULL");
			bzero(&rf, sizeof(rf));
			rf.code = QUARK_RF_FILE_EXEC_CHANGE;
			if (quark_rule_match_field(ctx->cur_rule, rf) != 0)
				ABORT("can't add match field");
		} | valuefield values {
			if (ctx->cur_rule == NULL)
				ABORT("parser bug, cur_rule is NULL");
			if (add_values(ctx, $1.rf.code) == -1)
				YYABORT;
		} ;

valuefield:	PROCESS_PID {
			$$.rf.code = QUARK_RF_PID;
		} | PROCESS_PPID {
			$$.rf.code = QUARK_RF_PPID;
		} | PROCESS_UID {
			$$.rf.code = QUARK_RF_UID;
		} | PROCESS_GID {
			$$.rf.code = QUARK_RF_GID;
		} | PROCESS_SID {
			$$.rf.code = QUARK_RF_SID;
		} | PROCESS_EXE {
			$$.rf.code = QUARK_RF_EXE;
		} | FILE_PATH {
			$$.rf.code = QUARK_RF_FILEPATH;
		} | EVENT_SCOPE {
			$$.rf.code = QUARK_RF_EVENT_SCOPE;
		} | POD_NAME {
			$$.rf.code = QUARK_RF_POD_NAME;
		} | CONTAINER_IMAGE {
			$$.rf.code = QUARK_RF_CONTAINER_IMAGE;
		} | POISON {
			$$.rf.code = QUARK_RF_POISON;
		} ;

/* One value, or a list of values that may span lines */
values:		value
		| '{' optnl valuelist optnl '}'
		;

valuelist:	value
		| valuelist optnl value
		;

value:		STRING {
			if (push_value(ctx, $1.str) == -1)
				ABORT("%s", strerror(errno));
		} ;

optnl:		/* empty */
		| optnl '\n'
		;

num_u64:	STRING {
			if (strtou64(&$$.num_u64, $1.str, 10) == -1)
				ABORT("bad number: %s", $1.str);
		} ;

%%
#undef ABORT

void
quark_error(struct quark_parser_ctx *ctx, const char *fmt, ...)
{
	va_list va;
	char	fmtbuf[1024];

	if (ctx->error)
		return;

	ctx->error = 1;

	va_start(va, fmt);
	snprintf(fmtbuf, sizeof(fmtbuf),
	    "quark_parse: %s at line %lu column %lu", fmt,
	    ctx->lineno + 1, ctx->colno + 1);
	vsnprintf(ctx->errorbuf, sizeof(ctx->errorbuf), fmtbuf, va);
	va_end(va);
}

/*
 * Start a line of the open block, an except line or an on line. The block
 * says which kind of rule it is.
 */
static int
line_begin(struct quark_parser_ctx *ctx, int except)
{
	int	action;

	if (ctx->ruleset->block_deny)
		action = except ? QUARK_RA_BLOCK_EXCEPT : QUARK_RA_BLOCK_ON;
	else
		action = except ? QUARK_RA_EXCEPT : QUARK_RA_TAG;
	ctx->cur_rule = quark_ruleset_append_rule(ctx->ruleset, action, 0);
	ctx->rule_lineno = ctx->lineno;

	return (ctx->cur_rule == NULL ? -1 : 0);
}

/*
 * The line has all its fields. A line of a block must be one that the
 * kernel can enforce, say why it is not.
 */
static int
line_end(struct quark_parser_ctx *ctx)
{
	struct quark_rule	*rule;
	const char		*why;

	rule = ctx->cur_rule;
	ctx->cur_rule = NULL;
	if (rule == NULL || !ctx->ruleset->block_deny)
		return (0);
	why = quark_ruleset_block_check_line(ctx->ruleset, rule);
	if (why == NULL)
		return (0);
	/* The lexer is past the newline, point at the line itself */
	ctx->lineno = ctx->rule_lineno;
	ctx->colno = 0;
	yyerror(ctx, "%s", why);

	return (-1);
}

/* Collect one value of the current field, the string is in the arena */
static int
push_value(struct quark_parser_ctx *ctx, const char *str)
{
	const char **new_strs;

	new_strs = reallocarray(ctx->strs, ctx->n_strs + 1,
	    sizeof(*ctx->strs));
	if (new_strs == NULL)
		return (-1);
	ctx->strs = new_strs;
	ctx->strs[ctx->n_strs++] = str;

	return (0);
}

/* Convert one string to a value of the field with the given code */
static int
value_from_string(struct quark_parser_ctx *ctx, u64 code, const char *str,
    struct quark_rule_field *rf)
{
	const char	*errstr;

	bzero(rf, sizeof(*rf));
	rf->code = code;

	switch (code) {
	case QUARK_RF_PID:		/* FALLTHROUGH */
	case QUARK_RF_PPID:		/* FALLTHROUGH */
	case QUARK_RF_UID:		/* FALLTHROUGH */
	case QUARK_RF_GID:		/* FALLTHROUGH */
	case QUARK_RF_SID:
		rf->pid = strtonum(str, 0, UINT32_MAX, &errstr);
		if (errstr != NULL) {
			yyerror(ctx, "bad number: %s: %s", str, errstr);
			return (-1);
		}
		break;
	case QUARK_RF_EXE:		/* FALLTHROUGH */
	case QUARK_RF_FILEPATH:		/* FALLTHROUGH */
	case QUARK_RF_POD_NAME:		/* FALLTHROUGH */
	case QUARK_RF_CONTAINER_IMAGE:
		/* Copied by quark_rule_match_field_list() */
		rf->wild.pre = (char *)str;
		break;
	case QUARK_RF_EVENT_SCOPE:
		if (!strcmp(str, "container"))
			rf->id = QUARK_RULE_SCOPE_CONTAINER;
		else if (!strcmp(str, "host"))
			rf->id = QUARK_RULE_SCOPE_HOST;
		else if (!strcmp(str, "unknown"))
			rf->id = QUARK_RULE_SCOPE_UNKNOWN;
		else {
			yyerror(ctx, "bad event scope: %s", str);
			return (-1);
		}
		break;
	case QUARK_RF_POISON:
		if (strtou64(&rf->poison_tag, str, 10) == -1) {
			yyerror(ctx, "bad number: %s", str);
			return (-1);
		}
		break;
	default:
		yyerror(ctx, "parser bug, bad field code %llu", code);
		return (-1);
	}

	return (0);
}

/*
 * Add the collected values to the current rule as one field, the values
 * are ORed. Always empties the collected values.
 */
static int
add_values(struct quark_parser_ctx *ctx, u64 code)
{
	struct quark_rule_field	*rfs;
	size_t			 i;
	int			 r;

	r = -1;
	if ((rfs = calloc(ctx->n_strs, sizeof(*rfs))) == NULL) {
		yyerror(ctx, "%s", strerror(errno));
		goto done;
	}
	for (i = 0; i < ctx->n_strs; i++) {
		if (value_from_string(ctx, code, ctx->strs[i], &rfs[i]) == -1)
			goto done;
	}
	if (quark_rule_match_field_list(ctx->cur_rule, rfs, ctx->n_strs) == -1) {
		yyerror(ctx, "can't add match field");
		goto done;
	}
	r = 0;
done:
	free(rfs);
	ctx->n_strs = 0;

	return (r);
}

/* Arena allocator so we can free intermediate allocations */
static char *
ctx_strdup(struct quark_parser_ctx *ctx, char *s)
{
	char **new_allocs;

	new_allocs = reallocarray(ctx->allocs, ctx->n_allocs + 1,
	    sizeof(char *));
	if (new_allocs == NULL)
		return (NULL);
	ctx->n_allocs++;
	ctx->allocs = new_allocs;
	ctx->allocs[ctx->n_allocs - 1] = strdup(s);

	return (ctx->allocs[ctx->n_allocs - 1]);
}

static struct keyword {
	const char	*word;
	int		 token;
} keywords[] = {
	{ "pass",		PASS },
	{ "drop",		DROP },
	{ "poison",		POISON },
	{ "on",			ON },
	{ "any",		ANY },
	{ "tag",		TAG },
	{ "except",		EXCEPT },
	{ "block",		BLOCK },
	{ "process.pid",	PROCESS_PID },
	{ "process.ppid",	PROCESS_PPID },
	{ "process.uid",	PROCESS_UID },
	{ "process.gid",	PROCESS_GID },
	{ "process.sid",	PROCESS_SID },
	{ "process.exe",	PROCESS_EXE },
	{ "file.path",		FILE_PATH },
	{ "file.exec_change",	FILE_EXEC_CHANGE },
	{ "event.scope",	EVENT_SCOPE },
	{ "pod.name",		POD_NAME },
	{ "container.image",	CONTAINER_IMAGE },
};

/*
 * quark_lex() borrows heavily from doas's yylex()
 *
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define ABORT(_fmt, ...) do {			\
	yyerror(ctx, _fmt, ##__VA_ARGS__);	\
	goto eof;				\
} while (0)

int
quark_lex(YYSTYPE *lvalp, struct quark_parser_ctx *ctx)
{
	char buf[4096], *ebuf, *p;
	int c, quoted = 0, quotes = 0, escape = 0, nonkw = 0;
	unsigned long qpos = 0;
	size_t i;

	if (ctx->sentnl)
		goto eof;

	p = buf;
	ebuf = buf + sizeof(buf);

repeat:
	/* skip whitespace first */
	for (c = getc(ctx->in); c == ' ' || c == '\t'; c = getc(ctx->in))
		ctx->colno++;

	/* check for special one-character constructions */
	switch (c) {
		case '\n':
			ctx->colno = 0;
			ctx->lineno++;
			return c;
		case '{':			/* FALLTHROUGH */
		case '}':
			ctx->colno++;
			return c;
		case '#':
			/* skip comments; NUL is allowed; no continuation */
			while ((c = getc(ctx->in)) != '\n')
				if (c == EOF)
					goto eof;
			ctx->colno = 0;
			ctx->lineno++;
			return c;
		case EOF:
			goto eof;
	}

	/* parsing next word */
	for (;; c = getc(ctx->in), ctx->colno++) {
		switch (c) {
		case '\0':
			ABORT("unallowed character NUL in column %lu",
			    ctx->colno + 1);
			escape = 0;
			continue;
		case '\\':
			escape = !escape;
			if (escape)
				continue;
			break;
		case '\n':
			if (quotes)
				ABORT("unterminated quotes in column %lu",
				    qpos + 1);
			if (escape) {
				nonkw = 1;
				escape = 0;
				ctx->colno = ULONG_MAX;
				ctx->lineno++;
				continue;
			}
			goto eow;
		case EOF:
			if (escape)
				ABORT("unterminated escape in column %lu",
				    ctx->colno);
			if (quotes)
				ABORT("unterminated quotes in column %lu",
				    qpos + 1);
			goto eow;
		case '#':
		case ' ':
		case '\t':
		case '{':
		case '}':
			if (!escape && !quotes)
				goto eow;
			break;
		case '"':
			if (!escape) {
				quoted = 1;
				quotes = !quotes;
				if (quotes) {
					nonkw = 1;
					qpos = ctx->colno;
				}
				continue;
			}
			break;
		}
		*p++ = c;
		if (p == ebuf)
			ABORT("too long line");
		escape = 0;
	}

eow:
	*p = 0;
	if (c != EOF)
		ungetc(c, ctx->in);
	if (p == buf) {
		/*
		 * There could be a number of reasons for empty buffer,
		 * and we handle all of them here, to avoid cluttering
		 * the main loop.
		 */
		if (c == EOF)
			goto eof;
		else if (!quoted)    /* accept empty args "" */
			goto repeat;
	}
	if (!nonkw) {
		for (i = 0; i < (int)nitems(keywords); i++) {
			if (strcmp(buf, keywords[i].word) == 0)
				return keywords[i].token;
		}
	}

	if ((lvalp->str = ctx_strdup(ctx, buf)) == NULL)
		ABORT("%s", strerror(errno));
	return STRING;

eof:
	if (ferror(ctx->in))
		ABORT("input error reading config");

	if (!ctx->sentnl) {
		ctx->sentnl = 1;
		return '\n';
	}

	return 0;

}
#undef ABORT
