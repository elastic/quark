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
 * Tags are set by tag blocks, one bit per distinct name, so they fit in
 * the u64 quark_event.tags. The names are log and alert for now, see
 * quark_ruleset_tag_begin().
 */
#define QUARK_MAX_TAGS		64

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

/*
 * Rule Condition, one field with one or more values. It matches when one
 * of the values matches. Each value has the same code.
 */
struct quark_rule_cond {
	u64			 code;		/* QUARK_RF_* */
	struct quark_rule_field	*values;	/* ORed */
	size_t			 n_values;	/* at least one */
};

struct quark_rule {
	struct quark_rule_cond	*conds;		/* conditions that must match */
	size_t			 n_conds;	/* number of conditions */
	int			 action;	/* QUARK_RA_* */
	u64			 poison_tag;	/* tag used for SETTING poison */
	u64			 evals;		/* counter */
	u64			 hits;		/* counter */
	u64			 tags;		/* TAG, EXCEPT: the bit of the block */
	u_int			 number;	/* starting from 0 */
	u_int			 skip_to;	/* TAG, EXCEPT: first rule after the block */
};

struct quark_ruleset {
	struct quark_rule	*rules;
	size_t			 n_rules;
	char			*tag_names[QUARK_MAX_TAGS];	/* by bit */
	u_int			 n_tags;
	/* The tag block being built, see quark_ruleset_tag_begin() */
	int			 block_open;
	int			 block_has_on;
	size_t			 block_start;
	u64			 block_tag;
};

struct quark_parser_ctx {
	struct quark_ruleset	 *ruleset;		/* parser output */
	struct quark_rule	 *cur_rule;		/* current rule we're processing */
	FILE			 *in;			/* input file */
	char			**allocs;		/* arena for parser allocations */
	size_t			  n_allocs;		/* size of the arena */
	const char		**strs;			/* values of the current field */
	size_t			  n_strs;		/* number of values */
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
int			 quark_rule_match_field_list(struct quark_rule *,
			     const struct quark_rule_field *, size_t);
struct quark_rule	*quark_ruleset_match(struct quark_ruleset *,
			     struct quark_event *);
int			 quark_ruleset_tag_begin(struct quark_ruleset *,
			     const char *);
int			 quark_ruleset_tag_end(struct quark_ruleset *);
const char		*quark_ruleset_tag_name(const struct quark_ruleset *,
			     u_int);

#endif /* _RULESET_H_ */
