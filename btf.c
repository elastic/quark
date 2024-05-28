#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "quark.h"

#include "libbpf/src/btf.h"
#include "libbpf/include/linux/err.h"		/* IS_ERR :( */

s32	btf_root_offset(struct btf *, const char *);

struct quark_btf targets[] = {
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
	{ "cred.user",			-1 },
	{ "dentry.d_name.name",		-1 },
	{ "dentry.d_parent",		-1 },
	{ "fs_struct.pwd.dentry",	-1 },
	{ "fs_struct.pwd.mnt",		-1 },
	{ "fs_struct.root.dentry",	-1 },
	{ "mm_struct.(anon).start_stack",-1 },
	{ "mount.mnt",			-1 },
	{ "mount.mnt_mountpoint",	-1 },
	{ "pid.numbers",		-1 },
	{ "signal_struct.pids",		-1 },
	{ "task_struct.comm",		-1 },
	{ "task_struct.cred",		-1 },
	{ "task_struct.exit_code",	-1 },
	{ "task_struct.fs",		-1 },
	{ "task_struct.group_leader",	-1 },
	{ "task_struct.mm",		-1 },
	{ "task_struct.pid",		-1 },
	{ "task_struct.start_boottime",	-1 },
	{ "task_struct.signal",		-1 },
	{ "task_struct.tgid",		-1 },
	{ "upid.nr",			-1 },
	{ "vfsmount.mnt_root",		-1 },
	{ NULL,				-1 },
	/* Keep this table in sync with enum btf_target_id */
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

s32
btf_root_offset(struct btf *btf, const char *dotname)
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

struct quark_btf *
quark_btf_open(void)
{
	struct btf		*btf;
	int			 failed;
	struct quark_btf	*ta, *qbtf;

	failed = 0;
	errno = 0;
	btf = btf__load_vmlinux_btf();
	if (IS_ERR_OR_NULL(btf)) {
		if (errno == 0)
			errno = ENOTSUP;
		return (NULL);
	}

	if ((qbtf = malloc(sizeof(targets))) == NULL)
		return (NULL);
	memcpy(qbtf, targets, sizeof(targets));

	for (ta = qbtf; ta->dotname != NULL; ta++) {
		ta->offset = btf_root_offset(btf, ta->dotname);
		if (ta->offset == -1) {
			warnx("%s: dotname=%s failed",
			    __func__, ta->dotname);
			failed++;
		}
	}

	for (ta = qbtf; quark_verbose && ta->dotname != NULL; ta++)
		fprintf(stderr, "%s: dotname=%s off=%ld (bitoff=%ld)\n",
		    __func__, ta->dotname, ta->offset, ta->offset * 8);

	btf__free(btf);

	if (failed) {
		quark_btf_close(qbtf);
		return (errno = ENOTSUP, NULL);
	}

	return (qbtf);
}

void
quark_btf_close(struct quark_btf *qbtf)
{
	free(qbtf);
}

ssize_t
quark_btf_offset(struct quark_btf *qbtf, const char *dotname)
{
	struct quark_btf *ta;

	for (ta = qbtf; ta->dotname != NULL; ta++) {
		if (!strcmp(ta->dotname, dotname)) {
			if (ta->offset != -1)
				return (ta->offset);
			break;
		}
	}

	return (-1);
}
