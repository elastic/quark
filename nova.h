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
/* Distinct process.exe patterns of all blocks, and file.path ones */
#define NOVA_BLOCK_MAX_PATHS	4096
/* Containers with metadata that a block can tell apart */
#define NOVA_BLOCK_MAX_CONTAINERS 16384
/*
 * A hook finds the container of a task in the name of its cgroup,
 * <prefix><id>.scope, as container_scope_lookup() in quark.c does. The id
 * is up to NOVA_CONTAINER_IDLEN lowercase hex characters, a longer one is
 * not a container for a block.
 */
#define NOVA_CONTAINER_IDLEN	64
#define NOVA_CGROUP_NAMELEN	128	/* including NUL */

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

/*
 * Key of the process.exe and file.path tries. A pattern that ends in * is
 * its bytes before the *, a fixed path is its bytes and the NUL, so a
 * lookup with the path of an operation finds the longest pattern that
 * matches. The value is a __u64 of line bits.
 */
struct nova_block_path_key {
	__u32	prefixlen;		/* in bits, of path */
	char	path[NOVA_PATHLEN];
	__u16	pad0;
};

/* Key of the container map: the id, padded with NUL */
struct nova_block_cid {
	char	id[NOVA_CONTAINER_IDLEN];
};

/* Counters of the block hooks, per CPU */
struct nova_block_stats {
	__u64	no_path;		/* a path was not resolved or too long */
	__u64	lost;			/* a denial that could not be reported */
};

/* What a block denied, nova_deny_event.op */
#define NOVA_OP_FORK		1
#define NOVA_OP_EXEC		2

/*
 * Input of the test program blk_test, which evaluates the blocks for a
 * made up operation as a hook does, see nova_block_test_run().
 */
#define NOVA_BT_PROCESS		0	/* kind: fork or exec, path is the executable */
#define NOVA_BT_FILE		1	/* kind: file operation, path is the file */
#define NOVA_BT_HAS_PATH	(1 << 0)	/* flags: path was resolved */
#define NOVA_BT_HAS_CBITS	(1 << 1)	/* flags: use cbits, not cgroup */

struct nova_block_test {
	__u32	kind;
	__u32	flags;
	__u64	cbits;				/* lines of the container */
	char	cgroup[NOVA_CGROUP_NAMELEN];	/* name of the cgroup */
	char	path[NOVA_PATHLEN];
	char	pad0[6];
};

/* Results of blk_test: 0 is allowed, 1 + n is denied by block n */
#define NOVA_BT_ALLOW		0
#define NOVA_BT_NOT_CONTAINER	1000
#define NOVA_BT_FAULT		1001

struct nova_rule_pcpu {
	__u64	hits;			/* counter */
	__u64	evals;			/* counter */
};

enum nova_kind {
	NOVA_INVALID,
	NOVA_FORK,
	NOVA_EXEC,
	NOVA_EXIT,
	NOVA_DENY,	/* struct nova_deny_event */
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

/*
 * An operation that a block denied. The size is fixed: a path that is
 * denied always fits in NOVA_PATHLEN, a longer one matches no line. So
 * the hooks need only the plain ring buffer calls.
 */
struct nova_deny_event {
	struct nova_event	ev;
	__u32			op;		/* NOVA_OP_* */
	__u32			block;		/* number of the block, from 0 */
	__u32			pid;		/* of the process that tried */
	__u32			tid;
	char			comm[16];
	char			path[NOVA_PATHLEN];	/* the executable */
	char			path2[NOVA_PATHLEN];	/* a second path, or empty */
	char			pad0[4];
} __aligned(8);

#if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 10))
#pragma GCC diagnostic pop
#endif

#endif /* _NOVA_H_ */
