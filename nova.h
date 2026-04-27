// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#ifndef _NOVA_H_
#define _NOVA_H_

#if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 10))
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wpadded"
#endif

/*
 * Redefine since we can't pull compat.h
 */
#ifndef __aligned
#define __aligned(x)	__attribute__((aligned(x)))
#endif	/* __aligned */

#define NOVA_MAX_RULES	1024
#define NOVA_MAX_PATHS	(NOVA_MAX_RULES * 2)
#define NOVA_PATHLEN	250	/* including NUL */

#define QUARK_RF_PID		(1ULL << 0)
#define QUARK_RF_PPID		(1ULL << 1)
#define QUARK_RF_UID		(1ULL << 2)
#define QUARK_RF_GID		(1ULL << 3)
#define QUARK_RF_SID		(1ULL << 4)
#define QUARK_RF_COMM		(1ULL << 5)
#define QUARK_RF_EXE		(1ULL << 6)
#define QUARK_RF_FILEPATH	(1ULL << 7)
#define QUARK_RF_POISON		(1ULL << 8)

enum quark_rule_action {
	QUARK_RA_INVALID,
	QUARK_RA_DROP,
	QUARK_RA_PASS,
	QUARK_RA_POISON,
};

struct path_lpm_key {
	__u32	prefixlen;
	__u16	meta;		/* upper 12 bits rule, 4 bits for type META_RF_*_* */
	char	path[NOVA_PATHLEN];
};

/*
 * path_lpm_key.meta
 */
#define META_RF_EXE			0x0001
#define META_RF_FILEPATH		0x0002
#define META_RF_MSK			0x000F
#define META_RF_SHIFT			0
#define META_RULE_MSK			0xFFF0
#define META_RULE_SHIFT			4
#define META_MAKE(_r, _k)						\
	((__u16)(_r) << META_RULE_SHIFT | (__u16)(_k) << META_RF_SHIFT)

/* 4 is sizeof(prefixlen) */
#define PATH_LPM_KEYLEN (sizeof(struct path_lpm_key) - 4)

struct nova_rule {
	__u64	fields;			/* QUARK_RF_* bitmask */
	__u64	poison_tag;		/* QUARK_RF_POISON */
	__u32	number;			/* starting from 0 */
	__u32	pid;			/* QUARK_RF_PID */
	__u32	ppid;			/* QUARK_RF_PPID */
	__u32	uid;			/* QUARK_RF_UID */
	__u32	gid;			/* QUARK_RF_GID */
	__u32	sid;			/* QUARK_RF_SID */
	__u32	action;			/* QUARK_RA_* */
	__u32	pad0;
	char	comm[16];		/* QUARK_RF_COMM */
};

struct nova_rule_pcpu {
	__u64	hits;			/* counter */
	__u64	evals;			/* counter */
} __aligned(8);

#if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 10))
#pragma GCC diagnostic pop
#endif

#endif /* _NOVA_H_ */
