#include <err.h>
#include <errno.h>
#include <stdio.h>

#include "quark.h"

#include "libbpf/src/btf.h"
#include "libbpf/include/linux/err.h"		/* IS_ERR :( */

enum target_id {
	TASK_STRUCT__CRED,
	CRED__USER
};

struct target {
	int		 id;
	const char	*dotname;
	ssize_t		 offset; /* NOTE: still in bits */
} targets[] = {
	{ TASK_STRUCT__CRED,	"task_struct.cred",	-1 },
	{ CRED__USER,		"cred.user",		-1 }
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

	return (off);
}

int
quark_btf_init(void)
{
	struct btf	*btf;
	int		 i, failed;
	struct target	*ta;

	btf = btf__load_vmlinux_btf();
	if (IS_ERR_OR_NULL(btf))
		return (-1);

	failed = 0;
	for (i = 0, ta = targets; i < (int)nitems(targets); i++, ta++) {
		ta->offset = btf_root_offset(btf, ta->dotname);
		if (ta->offset == -1) {
			warnx("%s: id=%d name=%s failed",
			    __func__, ta->id, ta->dotname);
			failed++;
		}
	}

	for (i = 0, ta = targets; i < (int)nitems(targets); i++, ta++)
		printf("%s: id=%d name=%s off=%ld\n",
		    __func__, ta->id, ta->dotname, ta->offset);

	btf__free(btf);

	return (failed ? -1 : 0);
}

ssize_t
quark_btf_offset(int id)
{
	return (targets[id].offset);
}
