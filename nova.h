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

#define NOVA_MAX_RULES		1024
/*
 * NOVA_PATH_FIELDS is how many META_RF_THINGs that are paths we have.
 * NOVA_MAX_PATHS is two paths (prefix + suffix) per rule per field
 */
#define NOVA_PATH_FIELDS	2
#define NOVA_MAX_PATHS		(NOVA_MAX_RULES * NOVA_PATH_FIELDS * 2)
#define NOVA_PATHLEN		250	/* including NUL */
/*
 * The "on" and "except on" lines of all blocks get one bit each in a
 * __u64, equal lines share a bit.
 */
#define NOVA_BLOCK_LINES	64
#define NOVA_MAX_BLOCKS		64

#define QUARK_RF_PID		(1ULL << 0)
#define QUARK_RF_PPID		(1ULL << 1)
#define QUARK_RF_UID		(1ULL << 2)
#define QUARK_RF_GID		(1ULL << 3)
#define QUARK_RF_SID		(1ULL << 4)
#define QUARK_RF_COMM		(1ULL << 5)
#define QUARK_RF_EXE		(1ULL << 6)
#define QUARK_RF_FILEPATH	(1ULL << 7)
#define QUARK_RF_POISON		(1ULL << 8)
#define QUARK_RF_FILE_EXEC_CHANGE (1ULL << 9)
#define QUARK_RF_EVENT_SCOPE	(1ULL << 10)
#define QUARK_RF_POD_NAME	(1ULL << 11)
#define QUARK_RF_CONTAINER_IMAGE (1ULL << 12)

/*
 * event.scope, every event has exactly one of the valid values.
 */
enum quark_rule_scope {
	QUARK_RULE_SCOPE_INVALID,
	QUARK_RULE_SCOPE_CONTAINER,	/* the cgroup names a container */
	QUARK_RULE_SCOPE_HOST,		/* a cgroup of the host layout */
	QUARK_RULE_SCOPE_UNKNOWN,	/* not enough evidence for either */
};

enum quark_rule_action {
	QUARK_RA_INVALID,
	QUARK_RA_DROP,
	QUARK_RA_PASS,
	QUARK_RA_POISON,
	QUARK_RA_TAG,		/* "on" line of a tag block, userspace only */
	QUARK_RA_EXCEPT,	/* "except on" line of a tag block, userspace only */
	QUARK_RA_BLOCK_ON,	/* "on" line of a block, never in userspace */
	QUARK_RA_BLOCK_EXCEPT,	/* "except on" line of a block, never in userspace */
};

/*
 * path_lpm value is a __u32 which is the length of the suffix
 * match. 0 means no suffix matching.
 */
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
#define META_RF_POSTFIX			0x8000 /* ORed for a postfix */
#define META_RF_MSK			0x000F
#define META_RF_SHIFT			0
#define META_RULE_MSK			0xFFF0
#define META_RULE_SHIFT			4
#define META_MAKE(_r, _k)						\
	((__u16)(_r) << META_RULE_SHIFT | (__u16)(_k) << META_RF_SHIFT)

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

/*
 * A block as two sets of line bits. With M the lines that match an
 * operation, the block denies it when (on & M) != 0 && (except & M) == 0.
 */
struct nova_block {
	__u64	on;
	__u64	except;
};

struct nova_rule_pcpu {
	__u64	hits;			/* counter */
	__u64	evals;			/* counter */
};

enum nova_kind {
	NOVA_INVALID,
	NOVA_FORK,
	NOVA_EXEC,
	NOVA_EXIT,
	NOVA_MAX,
};

struct nova_vl {
	__u32	off;
	__u32	len;
};

struct nova_task {
	struct nova_vl	vl_exe;
	struct nova_vl	vl_cwd;
	__u64		cap_perm;
	__u64		cap_eff;
	__u64		start_time_ns;
	__u32		tid;
	__u32		pid;	/* QUARK_RF_PID */
	__u32		ppid;	/* QUARK_RF_PPID */
	__u32		uid;	/* QUARK_RF_UID */
	__u32		gid;	/* QUARK_RF_GID */
	__u32		suid;
	__u32		sgid;
	__u32		euid;
	__u32		egid;
	__u32		pgid;
	__u32		sid;	/* QUARK_RF_SID */
	__u32		tty_major;
	__u32		tty_minor;
	__u32		uts_inonum;
	__u32		ipc_inonum;
	__u32		mnt_inonum;
	__u32		net_inonum;
	__u32		cgroup_inonum;
	__u32		time_inonum;
	__u32		pid_inonum;
	__u32		exit_code;
	__u32		pad0;
	char		comm[16];
};

struct nova_event {
	__u16	kind;		/* user filled */
	__u16	pad1;		/* zeroed */
	__u32	pad2;		/* zeroed */
	__u64	ts;		/* auto, ns since boot (CLOCK_BOOTTIME) */
} __aligned(8);

struct nova_task_event {
	struct nova_event	ev;
	struct nova_task	nt;
} __aligned(8);

#if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 10))
#pragma GCC diagnostic pop
#endif

#endif /* _NOVA_H_ */
