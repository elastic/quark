// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#ifndef _NOVA_H_
#define _NOVA_H_

#define NOVA_MAX_RULES	1024

#define QUARK_RF_PROCESS_PID		(1ULL << 0)
#define QUARK_RF_PROCESS_PPID		(1ULL << 1)
#define QUARK_RF_PROCESS_UID		(1ULL << 2)
#define QUARK_RF_PROCESS_GID		(1ULL << 3)
#define QUARK_RF_PROCESS_SID		(1ULL << 4)
#define QUARK_RF_PROCESS_COMM		(1ULL << 5)
#define QUARK_RF_PROCESS_FILENAME	(1ULL << 6)
#define QUARK_RF_FILE_PATH		(1ULL << 7)
#define QUARK_RF_POISON			(1ULL << 8)

enum quark_rule_action {
	QUARK_RA_INVALID,
	QUARK_RA_DROP,
	QUARK_RA_PASS,
	QUARK_RA_POISON,
};

struct nova_rule {
	enum quark_rule_action	action;
	__u64			fields;	/* QUARK_RF_* bitmask */
	__u32			pid;
	__u32			ppid;
	__u32			uid;
	__u32			gid;
	__u32			sid;
	char			comm[16];
	__u64			poison_tag;
};

#endif /* _NOVA_H_ */
