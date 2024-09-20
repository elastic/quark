// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/utsname.h>

#include "quark.h"

#include <bpf/btf.h>
#include "libbpf/include/linux/err.h"		/* IS_ERR :( */

s32	btf_root_offset(struct btf *, const char *);

struct quark_btf_target base_targets[] = {
	{ "cred.cap_ambient",		-1 },
	{ "cred.cap_bset",		-1 },
	{ "cred.cap_effective",		-1 },
	{ "cred.cap_inheritable",	-1 },
	{ "cred.cap_permitted",		-1 },
	{ "cred.egid",			-1 },
	{ "cred.euid",			-1 },
	{ "cred.gid",			-1 },
	{ "cred.sgid",			-1 },
	{ "cred.suid",			-1 },
	{ "cred.uid",			-1 },
	{ "dentry.d_name.name",		-1 },
	{ "dentry.d_parent",		-1 },
	{ "fs_struct.pwd.dentry",	-1 },
	{ "fs_struct.pwd.mnt",		-1 },
	{ "fs_struct.root.dentry",	-1 },
	{ "mm_struct.(anon).start_stack",-1 }, /* or mm_struct.start_stack */
	{ "mount.mnt",			-1 },
	{ "mount.mnt_mountpoint",	-1 },
	{ "pid.numbers",		-1 },
	{ "signal_struct.pids",		-1 },
	{ "signal_struct.tty",		-1 },
	{ "task_struct.comm",		-1 },
	{ "task_struct.cred",		-1 },
	{ "task_struct.exit_code",	-1 },
	{ "task_struct.fs",		-1 },
	{ "task_struct.group_leader",	-1 },
	{ "task_struct.mm",		-1 },
	{ "task_struct.pid",		-1 },
	{ "task_struct.pids",		-1 },
	{ "task_struct.real_parent",	-1 },
	{ "task_struct.start_boottime",	-1 }, /* or task_struct.real_start_time */
	{ "task_struct.signal",		-1 }, /* or task_struct.pids via KLUDGE */
	{ "task_struct.tgid",		-1 },
	{ "tty_driver.major",		-1 },
	{ "tty_driver.minor_start",	-1 },
	{ "tty_struct.driver",		-1 },
	{ "tty_struct.index",		-1 },
	{ "upid.nr",			-1 },
	{ "vfsmount.mnt_root",		-1 },
	{ NULL,				-1 },
};

struct btf_alternative {
	const char *new;
	const char *old;
} btf_alternatives[] = {
	{ "task_struct.start_boottime",		"task_struct.real_start_time"	},
	{ "mm_struct.(anon).start_stack",	"mm_struct.start_stack"		},
	{ NULL,					NULL				},
};

static const char *
btf_alternative_name(struct btf *btf, const char *new_name)
{
	struct btf_alternative	*p;

	for (p = btf_alternatives; p->new != NULL; p++) {
		if (strcmp(p->new, new_name))
			continue;

		if (quark_verbose)
			warnx("%s: found alternative for %s as %s",
			    __func__, p->new, p->old);
		return (p->old);
	}

	return (NULL);
}

static const struct btf_type *
btf_type_by_name_kind(struct btf *btf, s32 *off, const char *name, int kind)
{
	const struct btf_type *t;
	s32 off1;

	off1 = btf__find_by_name_kind(btf, name, kind);
	if (off1 < 0)
		return (NULL);
	t = btf__type_by_id(btf, off1);
	/* libbpf doesn't respect its own convention :( */
	if (IS_ERR_OR_NULL(t))
		return (NULL);
	if (off)
		*off = off1;

	return (t);
}

static const struct btf_member *
btf_offsetof(struct btf *btf, struct btf_type const *t, const char *mname)
{
	int			 i, vlen;
	const struct btf_member	*m;
	const char		*mname1;

	if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT)
		return (errno = EINVAL, NULL);
	vlen = BTF_INFO_VLEN(t->info);
	m = (const struct btf_member *)(t + 1);
	if (!strcmp(mname, "(anon)"))
		mname = "";

	for (i = 0; i < vlen; i++, m++) {
		mname1 = btf__name_by_offset(btf, m->name_off);
		if (IS_ERR_OR_NULL(mname1)) {
			warnx("%s: btf__name_by_offset(%d)",
			    __func__, m->name_off);
			continue;
		}
		if (strcmp(mname, mname1))
			continue;

		return (m);
	}

	return (NULL);
}

static s32
btf_root_offset2(struct btf *btf, const char *dotname)
{
	const struct btf_type *parent;
	const char *root_name, *child_name;
	const struct btf_member *m;
	char *last, buf[1024];
	s32 off;

	if (strlcpy(buf, dotname, sizeof(buf)) >= sizeof(buf))
		return (-1);
	root_name = strtok_r(buf, ".", &last);
	if (root_name == NULL)
		return (-1);
	/* root must be a struct */
	parent = btf_type_by_name_kind(btf, NULL, root_name, BTF_KIND_STRUCT);
	if (parent == NULL)
		return (-1);

	off = 0;
	while ((child_name = strtok_r(NULL, ".", &last)) != NULL) {
		m = btf_offsetof(btf, parent, child_name);
		if (m == NULL)
			return (-1);
		if (BTF_INFO_KFLAG(parent->info)) {
			off += BTF_MEMBER_BIT_OFFSET(m->offset);
			/* no bit_size things for now */
			if (BTF_MEMBER_BITFIELD_SIZE(m->offset) != 0)
				return (-1);
		} else
			off += m->offset;
		parent = btf__type_by_id(btf, m->type);
		if (IS_ERR_OR_NULL(parent))
			return (-1);
	}

	if ((off % 8) != 0)
		err(1, "bit offset not multiple of 8");

	return (off / 8);
}

s32
btf_root_offset(struct btf *btf, const char *dotname)
{
	s32	off;

	off = btf_root_offset2(btf, dotname);
	if (off != -1)
		return (off);

	/* Try a translation */
	dotname = btf_alternative_name(btf, dotname);
	if (dotname == NULL)
		return (-1);

	return (btf_root_offset2(btf, dotname));
}

static struct quark_btf *
quark_btf_new(const char *new_name)
{
	struct quark_btf	*qbtf;

	if ((qbtf = malloc(sizeof(*qbtf) + sizeof(base_targets))) == NULL)
		return (NULL);
	qbtf->kname = strdup(new_name);
	if (qbtf->kname == NULL) {
		free(qbtf);
		return (NULL);
	}
	memcpy(qbtf->targets, base_targets, sizeof(base_targets));

	return (qbtf);
}

static struct quark_btf *
quark_btf_dup(struct quark_btf *src)
{
	struct quark_btf	*qbtf;

	if (src == NULL)
		return (NULL);

	qbtf = quark_btf_new(src->kname);
	if (qbtf == NULL)
		return (NULL);
	memcpy(qbtf->targets, src->targets, sizeof(base_targets));

	return (qbtf);
}

struct quark_btf *
quark_btf_open_hub(const char *version)
{
	extern struct quark_btf	 *all_btfs[];
	struct quark_btf	**pp, *best, *cand;
	int			  best_score;

	/* paranoia */
	if (version == NULL || strlen(version) == 0)
		return (NULL);

	best = NULL;
	best_score = 0;
	for (pp = all_btfs; (cand = *pp) != NULL; pp++) {
		const char	*pv, *pc;
		int		 score;

		score = 0;

		/* paranoia */
		if (cand->kname == NULL || strlen(cand->kname) == 0)
			return (NULL);

		/*
		 * Match head, the beginning of version
		 */
		for (pc = cand->kname, pv = version, score = 0;
		     *pc != 0 && *pv != 0 && *pc == *pv;
		     score++, pc++, pv++)
			;     /* NADA */

		/*
		 * If we didn't score yet, don't bother matching tail
		 */
		if (score == 0)
			continue;

		/*
		 * Match tail, the end of version
		 */
		for (pc = cand->kname + strlen(cand->kname) - 1,
			 pv = version + strlen(version) - 1;
		     pc != cand->kname && pv != version && *pc == *pv;
		     score++, pc--, pv--)
			;	/* NADA */

		if (score > best_score) {
			best = cand;
			best_score = score;
		}
	}

	return (quark_btf_dup(best));
}

struct quark_btf *
quark_btf_open2(const char *path, const char *kname)
{
	struct btf		*btf;
	int			 failed;
	struct quark_btf	*qbtf;
	struct quark_btf_target *ta;

	failed = 0;
	errno = 0;
	if (path == NULL)
		btf = btf__load_vmlinux_btf();
	else
		btf = btf__parse(path, NULL);
	if (IS_ERR_OR_NULL(btf)) {
		if (errno == 0)
			errno = ENOTSUP;
		return (NULL);
	}

	if (kname == NULL)
		kname = "sys";
	if ((qbtf = quark_btf_new(kname)) == NULL)
		return (NULL);

	for (ta = qbtf->targets; ta->dotname != NULL; ta++) {
		ta->offset = btf_root_offset(btf, ta->dotname);
		if (ta->offset == -1) {
			/*
			 * Be stingy with printing things that always fail
			 */
			if (quark_verbose ||
			    (strcmp(ta->dotname, "signal_struct.pids") &&
			    strcmp(ta->dotname, "task_struct.pids")))
				warnx("%s: dotname=%s failed",
				    __func__, ta->dotname);

			failed++;
		}
	}

	btf__free(btf);

	for (ta = qbtf->targets; quark_verbose && ta->dotname != NULL; ta++)
		fprintf(stderr, "%s: dotname=%s off=%ld (bitoff=%ld)\n",
		    __func__, ta->dotname, ta->offset, ta->offset * 8);

	/*
	 * task_struct.signal is only present in new kernels, while
	 * task_struct.pids is only present in old kernels. If only one of
	 * either failed, it's all fine.
	 */
	if (failed == 1 &&
	    (quark_btf_offset(qbtf, "signal_struct.pids") == -1 ||
	    quark_btf_offset(qbtf, "task_struct.pids") == -1)) {
		failed = 0;
	}

	if (failed) {
		quark_btf_close(qbtf);
		return (errno = ENOTSUP, NULL);
	}

	return (qbtf);
}

struct quark_btf *
quark_btf_open(void)
{
	struct quark_btf	*qbtf;
	struct utsname		 uts;

	/* Try the system BTF */
	qbtf = quark_btf_open2(NULL, NULL);

	/* Try BTF hub */
	if (qbtf == NULL && uname(&uts) == 0)
		qbtf = quark_btf_open_hub(uts.release);

	return (qbtf);
}

void
quark_btf_close(struct quark_btf *qbtf)
{
	free(qbtf->kname);
	free(qbtf);
}

ssize_t
quark_btf_offset(struct quark_btf *qbtf, const char *dotname)
{
	struct quark_btf_target *ta;

	for (ta = qbtf->targets; ta->dotname != NULL; ta++) {
		if (!strcmp(ta->dotname, dotname)) {
			if (ta->offset != -1)
				return (ta->offset);
			break;
		}
	}

	return (-1);
}
