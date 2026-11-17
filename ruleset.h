/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Elastic NV */

#ifndef _RULESET_H_
#define _RULESET_H_

/*
 * Rule engine, see ruleset.c and the grammar in parse.y. Included by
 * quark.h, after compat.h and nova.h, never directly.
 */

struct quark_event;
struct quark_container;

/*
 * Tags are set by tag blocks, one bit per distinct name, so they fit in
 * the u64 quark_event.tags. The names are log and alert for now, see
 * quark_ruleset_tag_begin(). The name blocked is reserved for a denied
 * attempt, see quark_ruleset_block_begin().
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
	u_int			 n_blocks;	/* closed "block" blocks */
	u64			 blocked_tag;	/* bit of "blocked", 0 without blocks */
	/*
	 * The block being built, see quark_ruleset_tag_begin() and
	 * quark_ruleset_block_begin()
	 */
	int			 block_open;
	int			 block_deny;	/* a "block" block, not a tag block */
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
	u_long			  rule_lineno;		/* line of cur_rule */
	u_long			  lineno;		/* line number */
	u_long			  colno;		/* column number */
	int			  error;		/* if the parser errored out */
	char			  errorbuf[1024];	/* the parser error */
};

/*
 * The blocks of a ruleset compiled for the kernel, see block.c. Every
 * distinct line of every block is one bit, and all the sets below are sets
 * of lines.
 */

/* One process.exe or file.path pattern */
struct quark_block_path {
	char	*path;		/* bytes to compare, with the NUL when exact */
	size_t	 len;		/* number of bytes, 0 for "*" */
	int	 exact;		/* no "*", the whole path must be equal */
	u64	 own;		/* lines that have this pattern */
	u64	 lines;		/* own and those of every pattern that is a prefix */
};

struct quark_block_prog {
	const struct quark_ruleset	*ruleset;	/* borrowed, must not change */
	struct nova_block		 blocks[NOVA_MAX_BLOCKS];
	u_int				 n_blocks;
	u_int				 line_rule[NOVA_BLOCK_LINES];	/* a rule with this line */
	u_int				 n_lines;
	u64				 dc_exe;	/* lines without process.exe */
	u64				 dc_file;	/* lines without file.path */
	u64				 dc_container;	/* lines without a container field */
	struct quark_block_path		*exe;		/* sorted */
	size_t				 n_exe;
	struct quark_block_path		*file;		/* sorted */
	size_t				 n_file;
};

/* What a hook knows about an operation in a container */
enum quark_block_kind {
	QUARK_BLOCK_PROCESS,	/* fork or exec, the path is the executable */
	QUARK_BLOCK_FILE,	/* a file operation, the path is the file */
};

struct quark_block_input {
	enum quark_block_kind		 kind;
	const char			*path;		/* NULL if not resolved */
	const struct quark_container	*container;	/* NULL if no metadata */
};

/* block.c */
struct quark_block_prog	*quark_block_compile(const struct quark_ruleset *);
void			 quark_block_free(struct quark_block_prog *);
u64			 quark_block_container_bits(
			     const struct quark_block_prog *,
			     const struct quark_container *);
u64			 quark_block_path_bits(const struct quark_block_path *,
			     size_t, const char *);
int			 quark_block_eval(const struct quark_block_prog *,
			     const struct quark_block_input *);
int			 quark_block_eval_rules(const struct quark_ruleset *,
			     const struct quark_block_input *);

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
int			 quark_rule_match(const struct quark_rule *,
			     struct quark_event *);
int			 quark_rule_cond_match_container(
			     const struct quark_rule_cond *,
			     const struct quark_container *);
int			 quark_ruleset_tag_begin(struct quark_ruleset *,
			     const char *);
int			 quark_ruleset_tag_end(struct quark_ruleset *);
const char		*quark_ruleset_tag_name(const struct quark_ruleset *,
			     u_int);
int			 quark_ruleset_block_begin(struct quark_ruleset *);
int			 quark_ruleset_block_end(struct quark_ruleset *);
const char		*quark_ruleset_block_check_line(
			     const struct quark_ruleset *,
			     const struct quark_rule *);

#endif /* _RULESET_H_ */
