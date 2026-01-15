// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/utsname.h>

#include "quark.h"

#include <bpf/btf.h>

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
	{ "ipc_namespace.proc_inum",	-1 },  /* or ipc_namespace.ns.inum */
	{ "mm_struct.start_stack",	-1 },
	{ "mount.mnt",			-1 },
	{ "mount.mnt_mountpoint",	-1 },
	{ "mnt_namespace.proc_inum",	-1 },  /* or mnt_namespace.ns.inum */
	{ "net_namespace.proc_inum",	-1 },  /* or net.ns.inum or net.proc_inum */
	{ "nsproxy.ipc_ns",		-1 },
	{ "nsproxy.mnt_ns",		-1 },
	{ "nsproxy.net_ns",		-1 },
	{ "nsproxy.uts_ns",		-1 },
	{ "pid.numbers",		-1 },
	{ "pid_type.PIDTYPE_PGID",	-1 },
	{ "pid_type.PIDTYPE_SID",	-1 },
	{ "signal_struct.pids",		-1 },
	{ "signal_struct.tty",		-1 },
	{ "task_struct.comm",		-1 },
	{ "task_struct.cred",		-1 },
	{ "task_struct.exit_code",	-1 },
	{ "task_struct.fs",		-1 },
	{ "task_struct.group_leader",	-1 },
	{ "task_struct.mm",		-1 },
	{ "task_struct.nsproxy",	-1 },
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
	{ "uts_namespace.proc_inum",	-1 }, /* or uts_namespace.ns.inum */
	{ "vfsmount.mnt_root",		-1 },
	{ NULL,				-1 },
};

struct btf_alternative {
	const char *new;
	const char *old;
} btf_alternatives[] = {
	{ "task_struct.start_boottime",		"task_struct.real_start_time"	},
	{ "uts_namespace.proc_inum",		"uts_namespace.ns.inum"		},
	{ "ipc_namespace.proc_inum",		"ipc_namespace.ns.inum"		},
	{ "mnt_namespace.proc_inum",		"mnt_namespace.ns.inum"		},
	{ "net_namespace.proc_inum",		"net.ns.inum"			},
	{ "net_namespace.proc_inum",		"net.proc_inum"		 	},
	{ NULL,					NULL				},
};

static const struct btf_type *
btf_type_by_name_kind(struct btf *btf, s32 *off, const char *name, int kind)
{
	const struct btf_type *t;
	s32 off1;

	off1 = btf__find_by_name_kind(btf, name, kind);
	if (off1 < 0)
		return (NULL);
	t = btf__type_by_id(btf, off1);
	if (t == NULL)
		return (NULL);
	if (off)
		*off = off1;

	return (t);
}

/*
 * Given the structure or union type in t, find the offset of member_name.
 * In foo.bar, t would be the type of foo.
 */
static s32
btf_offsetof_rec(struct btf *btf, struct btf_type const *t, const char *member_name,
    struct btf_member **ret_member, s32 cur_off)
{
	int			 i;
	s32			 off;
	struct btf_member	*m;
	const char		*name;

	/*
	 * A const struct foo has kind const, not struct, and the struct itself
	 * is in the type member, so we have to dive in.
	 * XXX we should probably handle more than const here.
	 */
	if (btf_is_const(t)) {
		t = btf__type_by_id(btf, t->type);
		if (t == NULL)
			goto fail;
	}

	if (!btf_is_struct(t) && !btf_is_union(t)) {
		errno = EINVAL;
		goto fail;
	}
	m = btf_members(t);

	for (i = 0; i < btf_vlen(t); i++, m++) {
		name = btf__name_by_offset(btf, m->name_off);
		if (name == NULL)
			continue;

		/*
		 * Found it, make sure this is a multiple of 8.
		 */
		if (!strcmp(member_name, name)) {
			if (btf_kflag(t)) {
				off = BTF_MEMBER_BIT_OFFSET(m->offset);
				/* no bit_size things for now */
				if (BTF_MEMBER_BITFIELD_SIZE(m->offset) != 0)
					goto fail;
			} else
				off = m->offset;

			off += cur_off;
			if ((off % 8) != 0)
				goto fail;
			off /= 8;
			if (ret_member != NULL)
				*ret_member = m;

			return (off);
		}

		/*
		 * If this is an anonymous structure or union, recurse into it
		 * and see if we match member name.
		 */
		if (!strlen(name)) {
			struct btf_type const	*t1;

			t1 = btf__type_by_id(btf, m->type);
			if (t1 == NULL)
				continue;
			off = btf_offsetof_rec(btf, t1, member_name, ret_member,
			    cur_off + m->offset);
			if (off != -1)
				return (off);
		}
	}

fail:
	if (ret_member != NULL)
		*ret_member = NULL;

	return (-1);
}

/*
 * Given a struct or union parent_name, find member_name, return the offset
 * within that structure and, if ret_member is not NULL, return the btf_member
 * of member_name.
 */
static s32
btf_offsetof(struct btf *btf, const char *parent_name, const char *member_name,
    struct btf_member **ret_member)
{
	struct btf_type const	*parent_t;

	/*
	 * Parent must be a struct or a union
	 */
	parent_t = btf_type_by_name_kind(btf, NULL, parent_name, BTF_KIND_STRUCT);
	if (parent_t == NULL)
		parent_t = btf_type_by_name_kind(btf, NULL, parent_name,
		    BTF_KIND_UNION);
	if (parent_t == NULL) {
		if (ret_member != NULL)
			*ret_member = NULL;
		return (-1);
	}

	return (btf_offsetof_rec(btf, parent_t, member_name, ret_member, 0));

}

/*
 * Given a struct or union parent_name, find the btf_member{} of member_name.
 */
static struct btf_member *
btf_find_member(struct btf *btf, const char *parent_name, const char *member_name)
{
	struct btf_member *member = NULL;

	btf_offsetof(btf, parent_name, member_name, &member);

	return (member);
}

static s32
btf_root_offset2(struct btf *btf, const char *dotname)
{
	const char *root_name, *child_name;
	struct btf_member *m;
	const struct btf_type *t;
	char *last, buf[1024];
	s32 off, off1;

	if (strlcpy(buf, dotname, sizeof(buf)) >= sizeof(buf))
		return (-1);
	root_name = strtok_r(buf, ".", &last);
	if (root_name == NULL)
		return (-1);

	off = 0;
	t = NULL;
	while ((child_name = strtok_r(NULL, ".", &last)) != NULL) {
		m = NULL;
		/*
		 * t is NULL when we don't have the first type yet, we're
		 * looking for the type of root_name.
		 */
		if (t != NULL)
			off1 = btf_offsetof_rec(btf, t, child_name, &m, 0);
		else
			off1 = btf_offsetof(btf, root_name, child_name, &m);

		if (off1 == -1 || m == NULL)
			return (-1);
		off += off1;

		t = btf__type_by_id(btf, m->type);
		if (t == NULL)
			return (-1);
	}

	return (off);
}

/*
 * Given a dotname notation, find the offset within, dotname can be
 * sock.foo.bar.x, it will try to find the offset of x relative to sock.
 */
s32
btf_root_offset(struct btf *btf, const char *dotname, int alternatives)
{
	s32			 off;
	struct btf_alternative	*alt;

	off = btf_root_offset2(btf, dotname);
	if (off != -1)
		return (off);

	if (!alternatives)
		return (off);

	for (alt = btf_alternatives; alt->new != NULL; alt++) {
		if (strcmp(alt->new, dotname))
			continue;
		off = btf_root_offset2(btf, alt->old);
		if (off != -1) {
			qwarnx("found alternative for %s as %s (%d)",
			    dotname, alt->old, off);
			break;
		}
	}

	return (off);
}

static int
btf_enum_value(struct btf *btf, const char *dotname, ssize_t *uv)
{
	int			 i;
	const struct btf_type	*parent;
	const struct btf_enum	*v;
	char			 enum_type[256], enum_member[256];
	char			*dot;

	if (strlcpy(enum_type, dotname, sizeof(enum_type)) >=
	    sizeof(enum_type))
		return (-1);
	if ((dot = strchr(enum_type, '.')) == NULL)
		return (-1);
	*dot = 0;
	if (strlcpy(enum_member, dot + 1, sizeof(enum_member)) >=
	    sizeof(enum_member))
		return (-1);

	parent = btf_type_by_name_kind(btf, NULL, enum_type, BTF_KIND_ENUM);
	if (parent == NULL)
		return (-1);
	v = btf_enum(parent);
	for (i = 0; i < btf_vlen(parent); i++, v++) {
		if (strcmp(btf__name_by_offset(btf, v->name_off), enum_member))
			continue;

		*uv = v->val;
		return (0);
	}

	return (-1);
}

int
btf_number_of_params_of_ptr(struct btf *btf, const char *parent_name, const char *name)
{
	struct btf_member	*m;
	const struct btf_type	*t;

	m = btf_find_member(btf, parent_name, name);
	if (m == NULL)
		return (-1);
	t = btf__type_by_id(btf, m->type);
	if (t == NULL)
		return (-1);
	t = btf__type_by_id(btf, t->type);
	if (t == NULL)
		return (-1);
	if (!btf_is_func_proto(t))
		return (-1);

	return (btf_vlen(t));
}

int
btf_number_of_params(struct btf *btf, const char *func)
{
	const struct btf_type	*t;
	s32			 off;

	off = btf__find_by_name_kind(btf, func, BTF_KIND_FUNC);
	if (off < 0)
		return (-1);
	t = btf__type_by_id(btf, off);
	if (t == NULL)
		return (-1);
	t = btf__type_by_id(btf, t->type);
	if (t == NULL)
		return (-1);
	if (!btf_is_func_proto(t))
		return (-1);

	return (btf_vlen(t));
}

int
btf_index_of_param(struct btf *btf, const char *func, const char *param)
{
	s32			 off;
	struct btf_param	*bp;
	const struct btf_type	*t;
	const char		*cand;
	int			 i;

	off = btf__find_by_name_kind(btf, func, BTF_KIND_FUNC);
	if (off < 0)
		return (-1);
	t = btf__type_by_id(btf, off);
	if (t == NULL)
		return (-1);
	t = btf__type_by_id(btf, t->type);
	if (t == NULL)
		return (-1);

	for (i = 0, bp = btf_params(t); i < btf_vlen(t); i++, bp++) {
		cand = btf__name_by_offset(btf, bp->name_off);
		if (cand == NULL) {
			qwarnx("name for offset %d not found, "
			    "this is likely a bug", bp->name_off);
			continue;
		}
		/* found it */
		if (!strcmp(cand, param))
			return (i);
	}

	return (-1);
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
		     pc++, pv++, score++)
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
		     pc--, pv--, score++)
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
	if (btf == NULL) {
		if (errno == 0)
			errno = ENOTSUP;
		return (NULL);
	}

	if (kname == NULL)
		kname = "sys";
	if ((qbtf = quark_btf_new(kname)) == NULL)
		return (NULL);

	for (ta = qbtf->targets; ta->dotname != NULL; ta++) {
		ta->offset = btf_root_offset(btf, ta->dotname, 1);
		/* Maybe this is an enum */
		if (ta->offset == -1 &&
		    btf_enum_value(btf, ta->dotname, &ta->offset) == -1) {
			/*
			 * Be stingy with printing things that always fail
			 */
			if (quark_verbose >= QUARK_VL_DEBUG ||
			    (strcmp(ta->dotname, "signal_struct.pids") &&
			    strcmp(ta->dotname, "task_struct.pids"))) {
				qwarnx("dotname=%s failed", ta->dotname);
			}
			failed++;
		}
	}

	btf__free(btf);

	for (ta = qbtf->targets; ta->dotname != NULL; ta++)
		qdebugx("dotname=%s off=%ld (bitoff=%ld)",
		    ta->dotname, ta->offset, ta->offset * 8);

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
