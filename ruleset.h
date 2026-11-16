/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Elastic NV */

#ifndef _RULESET_H_
#define _RULESET_H_

/*
 * Rule engine, see ruleset.c and the grammar in parse.y. Included by
 * quark.h, after compat.h and nova.h, never directly.
 */

struct quark_event;

/*
 * post points into pre
 */
struct quark_wild {
	char	*pre;		/* user input, like foo*bar */
	size_t	 pre_len;
	char	*post;
	size_t	 post_len;
};

/* Rule Field */
struct quark_rule_field {
	u64		 code;
	union {
		u32			 pid;
		u64			 poison_tag;
		struct quark_wild	 wild;
		u32			 id;
		char			 comm[16];
	};
};

struct quark_rule {
	struct quark_rule_field	*fields;	/* fields that must match */
	size_t			 n_fields;	/* number of fields */
	int			 action;	/* QUARK_RA_* */
	u64			 poison_tag;	/* tag used for SETTING poison */
	u64			 evals;		/* counter */
	u64			 hits;		/* counter */
	u_int			 number;	/* starting from 0 */
};

struct quark_ruleset {
	struct quark_rule	*rules;
	size_t			 n_rules;
};

struct quark_parser_ctx {
	struct quark_ruleset	 *ruleset;		/* parser output */
	struct quark_rule	 *cur_rule;		/* current rule we're processing */
	FILE			 *in;			/* input file */
	char			**allocs;		/* arena for parser allocations */
	size_t			  n_allocs;		/* size of the arena */
	int			  sentnl;		/* if we sent nl uppon EOF */
	u_long			  lineno;		/* line number */
	u_long			  colno;		/* column number */
	int			  error;		/* if the parser errored out */
	char			  errorbuf[1024];	/* the parser error */
};

/* ruleset.c */
void			 quark_ruleset_init(struct quark_ruleset *);
void			 quark_ruleset_clear(struct quark_ruleset *);
int			 quark_ruleset_parse(struct quark_ruleset *, FILE *,
			     char *, size_t);
struct quark_rule	*quark_ruleset_append_rule(struct quark_ruleset *,
			     int, u64);
int			 quark_rule_match_field(struct quark_rule *,
			     struct quark_rule_field);
struct quark_rule	*quark_ruleset_match(struct quark_ruleset *,
			     struct quark_event *);

#endif /* _RULESET_H_ */
