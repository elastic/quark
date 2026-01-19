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
			u32			num_u32;
			u64			num_u64;
			struct quark_rule_field rf;
		};
		const char	*str;
	};
} quark_yystype;
#define QUARK_STYPE quark_yystype

void	quark_error(struct quark_parser_ctx *, const char *fmt, ...);
int	quark_lex(YYSTYPE *, struct quark_parser_ctx *);

#define ABORT(_fmt, ...) do {			\
	yyerror(ctx, _fmt, ##__VA_ARGS__);	\
	YYABORT;				\
} while (0)

%}

%define api.pure
%define api.prefix {quark_}
%define parse.error verbose
%parse-param {struct quark_parser_ctx *ctx}
%lex-param {struct quark_parser_ctx *ctx}
%initial-action {
	bzero(&$$, sizeof($$));
}

%token PASS DROP POISON ON ANY STRING
%token PROCESS_PID PROCESS_PPID PROCESS_UID PROCESS_GID PROCESS_SID
%token PROCESS_FILENAME FILE_PATH

%%
grammar:	/* empty  */
		| grammar '\n'
		| grammar rule '\n'
		| error { YYABORT; }
		;

rule:		action {
			ctx->cur_rule = quark_ruleset_append_rule(ctx->ruleset,
			    $1.action.code, $1.action.poison_tag);
			if (ctx->cur_rule == NULL)
				ABORT("can't add rule");
		} ON matchbody {
			ctx->cur_rule = NULL;
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

match:		matchfield {
			if (ctx->cur_rule == NULL)
				ABORT("parser bug, cur_rule is NULL");
			if (quark_rule_match_field(ctx->cur_rule, $1.rf) != 0)
				ABORT("can't add match field");
		} ;

matchfield:	PROCESS_PID num_u32 {
			$$.rf.code = QUARK_RF_PROCESS_PID;
			$$.rf.pid = $2.num_u32;
		} | PROCESS_PPID num_u32 {
			$$.rf.code = QUARK_RF_PROCESS_PPID;
			$$.rf.pid = $2.num_u32;
		} | PROCESS_UID num_u32 {
			$$.rf.code = QUARK_RF_PROCESS_UID;
			$$.rf.pid = $2.num_u32;
		} | PROCESS_GID num_u32 {
			$$.rf.code = QUARK_RF_PROCESS_GID;
			$$.rf.pid = $2.num_u32;
		} | PROCESS_SID num_u32 {
			$$.rf.code = QUARK_RF_PROCESS_SID;
			$$.rf.pid = $2.num_u32;
		} | PROCESS_FILENAME STRING {
			$$.rf.code = QUARK_RF_PROCESS_FILENAME;
			$$.rf.path =(char *)$2.str;
		} | FILE_PATH STRING {
			$$.rf.code = QUARK_RF_FILE_PATH;
			$$.rf.path =(char *)$2.str;
		} | POISON num_u64 {
			$$.rf.code = QUARK_RF_POISON;
			$$.rf.poison_tag = $2.num_u64;
		} ;

num_u32:	STRING {
			const char *errstr;

			$$.num_u32 = strtonum($1.str, 0, UINT32_MAX, &errstr);
			if (errstr != NULL)
				ABORT("bad number: %s: %s", $1.str, errstr);
		} ;

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
	{ "process.pid",	PROCESS_PID },
	{ "process.ppid",	PROCESS_PPID },
	{ "process.uid",	PROCESS_UID },
	{ "process.gid",	PROCESS_GID },
	{ "process.sid",	PROCESS_SID },
	{ "process.filename",	PROCESS_FILENAME },
	{ "file.path",		FILE_PATH },
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
