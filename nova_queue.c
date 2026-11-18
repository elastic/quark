// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#include <sys/epoll.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/sysinfo.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>

#include "quark.h"
#include "nova_skel.h"

struct nova_queue {
	struct nova		*nova;
	struct ring_buffer	*ringbuf;
	struct quark_block_prog	*blocks;	/* NULL without blocks */
	struct ring_buffer	*deny_ringbuf;	/* denied operations, with blocks */
};

static int	nova_queue_populate(struct quark_queue *);
static int	nova_queue_update_stats(struct quark_queue *);
static void	nova_queue_close(struct quark_queue *);
static void	nova_queue_container(struct quark_queue *,
		    const struct quark_container *, int);
static int	nova_deny_populate(struct quark_queue *, int);

struct quark_queue_ops queue_ops_nova = {
	.open	      = nova_queue_open,
	.populate     = nova_queue_populate,
	.update_stats = nova_queue_update_stats,
	.close	      = nova_queue_close,
	.container    = nova_queue_container,
};

/*
 * Alloc a path_lpm_key inside the probe, keyed by rule number + field type +
 * path.
 */
static int
alloc_path(struct nova_queue *nqq, int rule_i, struct quark_rule_field *field)
{
	struct path_lpm_key	key;
	u32			post_len;

	if (strlen(field->wild.pre) >= NOVA_PATHLEN ||
	    strlen(field->wild.post) >= NOVA_PATHLEN)
		return (errno = E2BIG, -1);

	bzero(&key, sizeof(key));

#ifdef HAVE_STATIC_ASSERT
	static_assert((NOVA_MAX_RULES - 1) <= (META_RULE_MSK >> META_RULE_SHIFT),
	    "NOVA_MAX_RULES cannot fit in META_RULE_MSK");
#endif

	switch (field->code) {
	case QUARK_RF_EXE:
		key.meta = META_MAKE(rule_i, META_RF_EXE);
		break;
	case QUARK_RF_FILEPATH:
		key.meta = META_MAKE(rule_i, META_RF_FILEPATH);
		break;
	default:
		qwarnx("unhandled code %llu", field->code);
		return (-1);
	}

	/*
	 * Calculate prefixlen, we always include at least key.meta, and then
	 * add pre_len
	 */
	key.prefixlen = (sizeof(key.meta) + field->wild.pre_len) * 8;

	if (strlcpy(key.path, field->wild.pre, sizeof(key.path)) >= sizeof(key.path))
		return (errno = E2BIG, -1);

	/*
	 * If there is no postfix, post_len is 0.
	 */
	post_len = field->wild.post_len;

	/*
	 * Install the prefix path
	 */
	if (bpf_map__update_elem(nqq->nova->maps.lpm_path,
	    &key, sizeof(key), &post_len, sizeof(post_len), BPF_ANY) != 0) {
		qwarn("bpf_map__update_elem pre %d", rule_i);
		return (-1);
	}

	/*
	 * Maybe install the postfix path
	 */
	if (post_len == 0)
		return (0);

	key.meta |= META_RF_POSTFIX;
	key.prefixlen = (sizeof(key.meta) + field->wild.post_len) * 8;

	/* Don't leak pre bytes into post, so zero it */
	bzero(key.path, sizeof(key.path));
	if (strlcpy(key.path, field->wild.post, sizeof(key.path)) >= sizeof(key.path))
		return (errno = E2BIG, -1);

	/* No post_len inside a postfix */
	post_len = 0;
	if (bpf_map__update_elem(nqq->nova->maps.lpm_path,
	    &key, sizeof(key), &post_len, sizeof(post_len), BPF_ANY) != 0) {
		qwarn("bpf_map__update_elem post %d", rule_i);
		return (-1);
	}

	return (0);
}

static int
nova_rule_from_quark(struct nova_queue *nqq,
    struct nova_rule *nr, struct quark_rule *qr)
{
	size_t			 i;
	struct quark_rule_cond	*cond;
	struct quark_rule_field *field;

	bzero(nr, sizeof(*nr));

	/* Tags run in userspace, the first match ends the loop in BPF */
	if (qr->action == QUARK_RA_TAG || qr->action == QUARK_RA_EXCEPT) {
		errno = ENOTSUP;
		qwarn("tag blocks are not supported in nova backend");
		return (-1);
	}
	/*
	 * The lines of a block go to the block maps, see load_blocks(). They
	 * keep their place in the rule array, where the loop skips them.
	 */
	if (qr->action == QUARK_RA_BLOCK_ON ||
	    qr->action == QUARK_RA_BLOCK_EXCEPT) {
		nr->number = qr->number;
		nr->action = qr->action;
		return (0);
	}

	for (i = 0; i < qr->n_conds; i++) {
		cond = qr->conds + i;
		if (cond->n_values != 1) {
			errno = ENOTSUP;
			qwarn("value lists are not supported in nova backend");
			return (-1);
		}
		field = cond->values;

		/*
		 * Two conditions on one field are ANDed in userspace. A
		 * nova_rule{} has one slot per field, the last value would
		 * win, and two paths would be ORed in lpm_path.
		 */
		if (nr->fields & field->code) {
			errno = ENOTSUP;
			qwarn("a field repeated in one rule is not supported "
			    "in nova backend");
			return (-1);
		}

		switch (field->code) {
		case QUARK_RF_PID:
			nr->pid = field->id;
			break;
		case QUARK_RF_PPID:
			nr->ppid = field->id;
			break;
		case QUARK_RF_UID:
			nr->uid = field->id;
			break;
		case QUARK_RF_GID:
			nr->gid = field->id;
			break;
		case QUARK_RF_SID:
			nr->sid = field->id;
			break;
		case QUARK_RF_COMM:
			strlcpy(nr->comm, field->comm, sizeof(nr->comm));
			break;
		case QUARK_RF_EXE:
			if ((alloc_path(nqq, qr->number, field)) == -1) {
				qwarn("exe alloc_path");
				return (-1);
			}
			break;
		case QUARK_RF_FILEPATH:
			if ((alloc_path(nqq, qr->number, field)) == -1) {
				qwarn("file_path alloc_path");
				return (-1);
			}
			break;
		case QUARK_RF_POISON:
			nr->poison_tag = field->poison_tag;
			break;
		case QUARK_RF_FILE_EXEC_CHANGE:
			errno = ENOTSUP;
			qwarn("file.exec_change is not supported in nova backend");
			return (-1);
			break;
		case QUARK_RF_EVENT_SCOPE:
			errno = ENOTSUP;
			qwarn("event.scope is not supported in nova backend");
			return (-1);
			break;
		case QUARK_RF_POD_NAME:
			errno = ENOTSUP;
			qwarn("pod.name is not supported in nova backend");
			return (-1);
			break;
		case QUARK_RF_CONTAINER_IMAGE:
			errno = ENOTSUP;
			qwarn("container.image is not supported in nova backend");
			return (-1);
			break;
		default:
			errno = EINVAL;
			qwarn("bad field->code %llu", field->code);
			return (-1);
			break;
		}

		nr->fields |= field->code;
	}

	nr->number = qr->number;
	nr->action = qr->action;

	return (0);
}

/*
 * The one place that opens the object: the skeleton call is a large
 * inline function, and a second copy of it does not inline.
 */
static __attribute__((noinline)) struct nova *
nova_open_object(void)
{
	return (nova__open());
}

/*
 * The blocks of a queue are in the nova backend, or in the enforcer next
 * to another backend, see nova_enforcer_open(). NULL for neither.
 */
static struct nova_queue *
block_nova_queue(struct quark_queue *qq)
{
	if (qq->enforcer != NULL)
		return (qq->enforcer);
	if (qq->queue_ops == &queue_ops_nova)
		return (qq->queue_be);

	return (NULL);
}

/* The hooks of the blocks, and where the skeleton keeps their links */
#define BLOCK_N_HOOKS	11

struct block_hook {
	struct bpf_program	 *prog;
	struct bpf_link		**link;
	int			  file;		/* a hook of the file blocks */
};

static void
block_hooks(struct nova *nova, struct block_hook hooks[BLOCK_N_HOOKS])
{
#define H(_i, _name, _file)						\
	hooks[_i] = (struct block_hook){ nova->progs._name,		\
	    &nova->links._name, _file }
	H(0, blk_bprm_check, 0);
	H(1, blk_task_alloc, 0);
	H(2, blk_path_mknod, 1);
	H(3, blk_path_chmod, 1);
	H(4, blk_file_open, 1);
	H(5, blk_path_truncate, 1);
	H(6, blk_file_truncate, 1);
	H(7, blk_path_rename, 1);
	H(8, blk_path_rename4, 1);
	H(9, blk_path_link, 1);
	H(10, blk_path_unlink, 1);
#undef H
}

/*
 * The number of arguments of an LSM hook in the running kernel, -1 if the
 * kernel has no such hook.
 */
static int
lsm_hook_nargs(const struct btf *btf, const char *hook)
{
	const struct btf_type	*t;
	char			 name[64];
	int			 id;

	if (snprintf(name, sizeof(name), "bpf_lsm_%s", hook) >=
	    (int)sizeof(name))
		return (-1);
	id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
	if (id <= 0 || (t = btf__type_by_id(btf, id)) == NULL ||
	    (t = btf__type_by_id(btf, t->type)) == NULL ||
	    !btf_is_func_proto(t))
		return (-1);

	return (btf_vlen(t));
}

/*
 * What the running kernel has for the file hooks, from its BTF. Two hooks
 * are not the same in every kernel:
 * - path_rename has four arguments up to Linux 5.18 and five since, and
 *   there is one program for each form.
 * - file_truncate is there since Linux 6.2.
 * Returns -1 with errno set to ENOTSUP if the kernel has no path hooks, it
 * then lacks CONFIG_SECURITY_PATH.
 */
static int
file_hooks_probe(int *rename_nargs, int *file_truncate)
{
	struct btf	*btf;

	if ((btf = btf__load_vmlinux_btf()) == NULL) {
		qwarn("can't load the kernel BTF");
		return (errno = ENOTSUP, -1);
	}
	*rename_nargs = lsm_hook_nargs(btf, "path_rename");
	*file_truncate = lsm_hook_nargs(btf, "file_truncate") != -1;
	btf__free(btf);
	if (*rename_nargs != 4 && *rename_nargs != 5) {
		qwarnx("a block on file.path needs the path hooks of the "
		    "kernel, CONFIG_SECURITY_PATH");
		return (errno = ENOTSUP, -1);
	}

	return (0);
}

/*
 * Choose the programs of the blocks to load: the test program, and the
 * hooks that the compiled blocks need, none for hooks == 0. A ruleset
 * without a block on file.path does not pay for the file hooks, and the
 * other way around. No hook attaches by itself, see attach_blocks().
 */
static int
block_programs(struct nova_queue *nqq, int hooks)
{
	struct nova		*nova = nqq->nova;
	struct block_hook	 bh[BLOCK_N_HOOKS];
	int			 i, load, process, file;
	int			 rename_nargs = 0, file_truncate = 0;

	process = hooks && nqq->blocks != NULL && nqq->blocks->n_exe > 0;
	file = hooks && nqq->blocks != NULL && nqq->blocks->n_file > 0;
	if (file && file_hooks_probe(&rename_nargs, &file_truncate) == -1)
		return (-1);
	block_hooks(nova, bh);
	for (i = 0; i < BLOCK_N_HOOKS; i++) {
		load = bh[i].file ? file : process;
		if (bh[i].prog == nova->progs.blk_path_rename)
			load = load && rename_nargs == 5;
		else if (bh[i].prog == nova->progs.blk_path_rename4)
			load = load && rename_nargs == 4;
		else if (bh[i].prog == nova->progs.blk_file_truncate)
			load = load && file_truncate;
		bpf_program__set_autoload(bh[i].prog, load);
		bpf_program__set_autoattach(bh[i].prog, 0);
	}
	bpf_program__set_autoload(nova->progs.blk_test, nqq->blocks != NULL);
	/* blk_test is run with BPF_PROG_TEST_RUN, never attached */
	bpf_program__set_autoattach(nova->progs.blk_test, 0);
	/* Only the file hooks build a path */
	bpf_map__set_autocreate(nova->maps.blk_scratch, file);

	return (0);
}

/*
 * Load what the blocks need and nothing else: none of the programs that
 * send events, and none of their maps. What is left needs Linux 5.17, the
 * other programs need 5.19.
 */
static int
nova_blocks_only(struct nova_queue *nqq, int hooks)
{
	struct nova		*nova = nqq->nova;
	struct bpf_program	*prog;

	bpf_object__for_each_program(prog, nova->obj)
		bpf_program__set_autoload(prog, 0);
	bpf_map__set_autocreate(nova->maps.scratch_eval, 0);
	bpf_map__set_autocreate(nova->maps.lpm_path, 0);
	bpf_map__set_autocreate(nova->maps.ruleset, 0);
	bpf_map__set_autocreate(nova->maps.ruleset_pcpu, 0);
	bpf_map__set_autocreate(nova->maps.output_ring, 0);

	return (block_programs(nqq, hooks));
}

#define NOVA_LSM_LIST	"/sys/kernel/security/lsm"

/*
 * A block needs the BPF LSM to be active: without it the programs load
 * and attach, and never run, so nothing would be denied and nobody would
 * know. It is active when "bpf" is in the list of securityfs. Returns -1
 * with errno set to ENOTSUP.
 */
static int
check_bpf_lsm(void)
{
	char	 buf[1024], *tok, *next;
	ssize_t	 n;
	int	 fd;

	if ((fd = open(NOVA_LSM_LIST, O_RDONLY)) == -1) {
		qwarn("blocks need the BPF LSM, can't open %s, "
		    "is securityfs mounted?", NOVA_LSM_LIST);
		return (errno = ENOTSUP, -1);
	}
	n = qread(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0) {
		qwarn("can't read %s", NOVA_LSM_LIST);
		return (errno = ENOTSUP, -1);
	}
	buf[n] = 0;
	buf[strcspn(buf, "\n")] = 0;
	for (next = buf; (tok = strsep(&next, ",")) != NULL; ) {
		if (!strcmp(tok, "bpf"))
			return (0);
	}
	qwarnx("blocks need the BPF LSM, which is not active: boot with "
	    "lsm=...,bpf");

	return (errno = ENOTSUP, -1);
}

/*
 * Compile the blocks of a ruleset, and set what the programs of the
 * blocks take as constants.
 */
static int
load_block_rodata(struct nova_queue *nqq, const struct quark_ruleset *ruleset,
    int host)
{
	struct nova	*nova = nqq->nova;

	if ((nqq->blocks = quark_block_compile(ruleset)) == NULL) {
		qwarn("can't compile blocks");
		return (-1);
	}
	nova->rodata->blk_n_blocks = nqq->blocks->n_blocks;
	nova->rodata->blk_dc_exe = nqq->blocks->dc_exe;
	nova->rodata->blk_dc_file = nqq->blocks->dc_file;
	nova->rodata->blk_dc_container = nqq->blocks->dc_container;
	nova->rodata->blk_host = host;

	return (0);
}

/*
 * Set what the programs take as constants. The programs of the blocks are
 * loaded only when the ruleset has a block.
 */
static int
load_rodata(struct quark_queue *qq, struct nova_queue *nqq)
{
	struct nova	*nova = nqq->nova;

	if (qq->ruleset != NULL) {
		if (qq->ruleset->n_rules > NOVA_MAX_RULES)
			return (errno = EFBIG, -1);
		nova->rodata->rules_active = qq->ruleset->n_rules;
		if (qq->ruleset->n_blocks > 0) {
			if (check_bpf_lsm() == -1)
				return (-1);
			if (load_block_rodata(nqq, qq->ruleset,
			    (qq->flags & QQ_BLOCK_HOST) != 0) == -1)
				return (-1);
		}
	}

	return (block_programs(nqq, 1));
}

/* Install the patterns of one field in its trie */
static int
load_block_paths(struct bpf_map *map, const struct quark_block_path *paths,
    size_t n_paths)
{
	struct nova_block_path_key	key;
	const struct quark_block_path	*bp;
	__u64				lines;
	size_t				i;

	if (n_paths > NOVA_BLOCK_MAX_PATHS)
		return (errno = E2BIG, -1);
	for (i = 0; i < n_paths; i++) {
		bp = paths + i;
		/* quark_ruleset_block_check_line() limits the pattern */
		if (bp->len > sizeof(key.path))
			return (errno = E2BIG, -1);
		bzero(&key, sizeof(key));
		memcpy(key.path, bp->path, bp->len);
		key.prefixlen = bp->len * 8;
		lines = bp->lines;
		if (bpf_map__update_elem(map, &key, sizeof(key),
		    &lines, sizeof(lines), BPF_ANY) != 0)
			return (-1);
	}

	return (0);
}

/*
 * Install the compiled blocks. This runs after the load and before the
 * attach, so that a hook never sees a part of them.
 */
static int
load_blocks(struct nova_queue *nqq)
{
	struct nova		*nova = nqq->nova;
	struct quark_block_prog	*blocks = nqq->blocks;
	u32			 i;

	if (blocks == NULL)
		return (0);
	for (i = 0; i < blocks->n_blocks; i++) {
		if (bpf_map__update_elem(nova->maps.blk_blocks, &i, sizeof(i),
		    &blocks->blocks[i], sizeof(blocks->blocks[i]),
		    BPF_ANY) != 0) {
			qwarn("can't install block %u", i);
			return (-1);
		}
	}
	if (load_block_paths(nova->maps.blk_path_exe,
	    blocks->exe, blocks->n_exe) == -1) {
		qwarn("can't install the process.exe patterns of blocks");
		return (-1);
	}
	if (load_block_paths(nova->maps.blk_path_file,
	    blocks->file, blocks->n_file) == -1) {
		qwarn("can't install the file.path patterns of blocks");
		return (-1);
	}

	return (0);
}

/*
 * A denied operation from a hook of the blocks becomes a raw event, which
 * the queue orders by time with the events of the backend.
 */
static int
nova_deny_cb(void *vqq, void *vdata, size_t len)
{
	struct quark_queue	*qq = vqq;
	struct nova_deny_event	*ev = vdata;
	struct raw_event	*raw;
	struct quark_blocked	*blocked;

	if (len < sizeof(*ev) || ev->ev.kind != NOVA_DENY) {
		qwarnx("unexpected event in the ring of the blocks");
		return (0);
	}
	if ((raw = raw_event_alloc(RAW_BLOCKED)) == NULL)
		return (0);
	raw->pid = ev->pid;
	raw->tid = ev->tid;
	raw->time = ev->ev.ts;
	blocked = &raw->blocked.quark_blocked;
	blocked->op = ev->op;
	blocked->block = ev->block;
	blocked->pid = ev->pid;
	blocked->tid = ev->tid;
	/*
	 * The ring is read only for us, and its strings may lack a NUL:
	 * copy with a bound, then terminate the copy. raw_event_alloc()
	 * gave us zeroes.
	 */
	memcpy(blocked->comm, ev->comm, sizeof(blocked->comm) - 1);
	memcpy(blocked->path, ev->path, sizeof(blocked->path) - 1);
	memcpy(blocked->path2, ev->path2, sizeof(blocked->path2) - 1);
	if (raw_event_insert(qq, raw) == -1)
		raw_event_free(raw);

	return (0);
}

/* The ring of the denied operations, watched by the epoll of the queue */
static int
deny_ringbuf_setup(struct quark_queue *qq, struct nova_queue *nqq)
{
	struct epoll_event	ev;
	int			fd;

	if (nqq->blocks == NULL)
		return (0);
	nqq->deny_ringbuf = ring_buffer__new(
	    bpf_map__fd(nqq->nova->maps.blk_ring), nova_deny_cb, qq, NULL);
	if (nqq->deny_ringbuf == NULL) {
		qwarn("can't setup the ring of the blocks");
		return (-1);
	}
	if ((fd = ring_buffer__epoll_fd(nqq->deny_ringbuf)) < 0) {
		qwarnx("ring_buffer__epoll_fd failed");
		goto fail;
	}
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(qq->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		qwarn("epoll_ctl");
		goto fail;
	}
	qq->deny_populate = nova_deny_populate;

	return (0);
fail:
	/* this closes the fd */
	ring_buffer__free(nqq->deny_ringbuf);
	nqq->deny_ringbuf = NULL;

	return (-1);
}

static void
deny_ringbuf_close(struct quark_queue *qq, struct nova_queue *nqq)
{
	int	fd;

	if (nqq->deny_ringbuf == NULL)
		return;
	qq->deny_populate = NULL;
	fd = ring_buffer__epoll_fd(nqq->deny_ringbuf);
	if (fd >= 0 && qq->epollfd != -1 &&
	    epoll_ctl(qq->epollfd, EPOLL_CTL_DEL, fd, NULL) == -1)
		qwarn("epoll_ctl EPOLL_CTL_DEL");
	ring_buffer__free(nqq->deny_ringbuf);
	nqq->deny_ringbuf = NULL;
}

/*
 * Take up to max denied operations out of their ring, quark_queue.
 * deny_populate. The queue says how many, see quark_queue_populate().
 */
static int
nova_deny_populate(struct quark_queue *qq, int max)
{
	struct nova_queue	*nqq = block_nova_queue(qq);
	int			 npop;

	if (nqq == NULL || nqq->deny_ringbuf == NULL || max <= 0)
		return (0);
	npop = ring_buffer__consume_n(nqq->deny_ringbuf, max);

	return (npop < 0 ? -1 : npop);
}

/*
 * Attach the hooks of the blocks, after the others. With two programs on
 * one hook the kernel runs the last attached first, and the first that
 * denies ends the chain. The hook of a block must be that one: a denied
 * exec is not an exec, and the program that sends events must not see it.
 * This order is not a documented interface, t_block_process_nova tests
 * it.
 */
static int
attach_blocks(struct nova_queue *nqq)
{
	struct block_hook	 bh[BLOCK_N_HOOKS];
	int			 i;

	if (nqq->blocks == NULL)
		return (0);
	block_hooks(nqq->nova, bh);
	for (i = 0; i < BLOCK_N_HOOKS; i++) {
		if (!bpf_program__autoload(bh[i].prog))
			continue;
		*bh[i].link = bpf_program__attach(bh[i].prog);
		if (*bh[i].link == NULL) {
			qwarn("can't attach %s", bpf_program__name(bh[i].prog));
			return (-1);
		}
	}

	return (0);
}

/*
 * For tests: the blocks of a ruleset in the kernel, with their maps and
 * the test program, and no hook. Nothing is attached, so nothing on the
 * machine is denied, whatever the blocks say. nova_block_test_run()
 * evaluates a made up operation with the code of the hooks, host is
 * QQ_BLOCK_HOST: a cgroup that is not a container is evaluated. Returns a
 * handle for the other two calls, or NULL with errno set, EINVAL for a
 * ruleset without blocks.
 */
void *
nova_block_test_open(const struct quark_ruleset *ruleset, int host)
{
	struct nova_queue	*nqq;

	if (ruleset == NULL || ruleset->n_blocks == 0)
		return (errno = EINVAL, NULL);
	setup_libbpf_logs();
	if ((nqq = calloc(1, sizeof(*nqq))) == NULL)
		return (NULL);
	if ((nqq->nova = nova_open_object()) == NULL)
		goto fail;
	if (load_block_rodata(nqq, ruleset, host) == -1)
		goto fail;
	if (nova_blocks_only(nqq, 0) == -1)
		goto fail;
	if (nova__load(nqq->nova) != 0)
		goto fail;
	if (load_blocks(nqq) == -1)
		goto fail;

	return (nqq);
fail:
	nova_block_test_close(nqq);

	return (NULL);
}

/*
 * Returns NOVA_BT_ALLOW, 1 + the number of the block that denies,
 * NOVA_BT_NOT_CONTAINER when the cgroup name is not a container, or -1
 * with errno set.
 */
int
nova_block_test_run(void *handle, const struct nova_block_test *in)
{
	struct nova_queue	*nqq = handle;
	__u64			 args[1];
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	args[0] = (__u64)(unsigned long)in;
	opts.ctx_in = args;
	opts.ctx_size_in = sizeof(args);
	if (bpf_prog_test_run_opts(
	    bpf_program__fd(nqq->nova->progs.blk_test), &opts) != 0)
		return (-1);

	return (opts.retval);
}

void
nova_block_test_close(void *handle)
{
	struct nova_queue	*nqq = handle;
	int			 saved_errno = errno;

	if (nqq == NULL)
		return;
	if (nqq->nova != NULL)
		nova__destroy(nqq->nova);
	quark_block_free(nqq->blocks);
	free(nqq);
	errno = saved_errno;
}

/*
 * Walk over all rules, make a nova_rule{} out of a quark_rule{} and install it
 * in the bpf rule map.
 */
static int
load_ruleset(struct quark_queue *qq, struct nova_queue *nqq)
{
	u32			 i;
	struct nova		*nova;
	struct nova_rule	 nr;

	if (qq->ruleset == NULL)
		return (0);
	if (qq->ruleset->n_rules > NOVA_MAX_RULES)
		return (errno = EFBIG, -1);
	if (qq->ruleset->n_rules != nqq->nova->rodata->rules_active)
		return (errno = EINVAL, -1);
	if ((nova = nqq->nova) == NULL)
		return (errno = EINVAL, -1);

	for (i = 0; i < (u32)qq->ruleset->n_rules; i++) {
		if (nova_rule_from_quark(nqq, &nr,
		    qq->ruleset->rules + i) == -1) {
			qwarn("quark_rule_to_nova");
			return (-1);
		}
		if (bpf_map__update_elem(nova->maps.ruleset, &i, sizeof(i),
		    &nr, sizeof(nr), BPF_ANY) != 0) {
			qwarn("bpf_map__update_elem %d", i);
			return (-1);
		}
	}

	return (0);
}

static const char *
nova_kind_str(enum nova_kind kind)
{
	switch (kind) {
	case NOVA_FORK:
		return ("NOVA_FORK");
	case NOVA_EXEC:
		return ("NOVA_EXEC");
	case NOVA_EXIT:
		return ("NOVA_EXIT");
	default:
		return ("?");
	}
}

/*
 * nova_vl to char *
 * NOTE: if we pass qq here we could add some basic bound checks for rogue
 * events.
 */
static const char *
vltoc(void *vnev, struct nova_vl *vl)
{
	struct nova_event	*nev = vnev;

	if (vl->len == 0)
		return (NULL);

	return (((const char *)nev) + vl->off);
}

static int
nova_ringbuf_cb(void *vqq, void *vdata, size_t len)
{
	/* struct quark_queue	*qq = vqq; */
	struct nova_event	*nev;
	struct nova_task	*nt;
	struct nova_task_event	*nte;

	nev = vdata;
	nt = NULL;
	nte = NULL;

	printf("nova event %s len=%zd ts=%llu ",
	    nova_kind_str(nev->kind), len, nev->ts);

	switch (nev->kind) {
	case NOVA_FORK:		/* FALLTHROUGH */
	case NOVA_EXEC:		/* FALLTHROUGH */
	case NOVA_EXIT:
		nte = (struct nova_task_event *)nev;
		nt = &nte->nt;
		printf("pid=%d exe=%s cap_eff=0x%llx cap_perm=0x%llx uid=%d gid=%d comm=%s cwd=%s ",
		    nt->pid, vltoc(nte, &nt->vl_exe), nt->cap_eff, nt->cap_perm, nt->uid,
		    nt->gid, nt->comm, vltoc(nte, &nt->vl_cwd));
		break;
	default:
		putchar('?');
		break;
	}

	putchar('\n');

	return (0);
}

static int
ringbuf_setup(struct quark_queue *qq, struct nova_queue *nqq)
{
	int			ringbuf_fd;
	struct epoll_event	ev;

	nqq->ringbuf = ring_buffer__new(bpf_map__fd(nqq->nova->maps.output_ring),
	    nova_ringbuf_cb, qq, NULL);
	if (nqq->ringbuf == NULL) {
		qwarn("can't setup ringbuf");
		goto fail;
	}

	ringbuf_fd = ring_buffer__epoll_fd(nqq->ringbuf);
	if (ringbuf_fd < 0) {
		qwarnx("ring_buffer__epoll_fd failed");
		goto fail;
	}
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = ringbuf_fd;
	if (epoll_ctl(qq->epollfd, EPOLL_CTL_ADD, ringbuf_fd, &ev) == -1) {
		qwarn("epoll_ctl");
		goto fail;
	}
	/*
	 * FUTURE: if you add code here, you must undo the epoll_ctl() above in
	 * fail:
	 */

	return (0);
fail:
	if (nqq->ringbuf != NULL) {
		/* this closes ringbuf_fd! */
		ring_buffer__free(nqq->ringbuf);
		nqq->ringbuf = NULL;
	}

	return (-1);
}

int
nova_queue_open(struct quark_queue *qq)
{
	struct nova_queue	*nqq;
	struct bpf_program	*prog;

	if ((qq->flags & QQ_NOVA) == 0)
		return (errno = ENOTSUP, -1);

	setup_libbpf_logs();

	if ((nqq = calloc(1, sizeof(*nqq))) == NULL)
		return (-1);
	qq->queue_be = nqq;

	if ((nqq->nova = nova_open_object()) == NULL)
		goto fail;
	bpf_object__for_each_program(prog, nqq->nova->obj) {
		/* bpf_program__set_autoload(prog, 0); */
		if (quark_verbose >= QUARK_VL_DEBUG)
			bpf_program__set_log_level(prog, 1);
	}
	if (load_rodata(qq, nqq) == -1)
		goto fail;
	if (nova__load(nqq->nova) != 0)
		goto fail;
	if (load_ruleset(qq, nqq) == -1)
		goto fail;
	if (load_blocks(nqq) == -1)
		goto fail;
	if (ringbuf_setup(qq, nqq) == -1)
		goto fail;
	if (deny_ringbuf_setup(qq, nqq) == -1)
		goto fail;
	if (nova__attach(nqq->nova) != 0)
		goto fail;
	if (attach_blocks(nqq) == -1)
		goto fail;

	qq->queue_ops = &queue_ops_nova;
	qq->stats.backend = QQ_NOVA;

	return (0);
fail:
	nova_queue_close(qq);
	return (-1);
}

static int
nova_queue_populate(struct quark_queue *qq)
{
	struct nova_queue	*nqq = qq->queue_be;
	int			 npop, space_left;

	space_left =
	    qq->flags & QQ_BYPASS ? 1 :
	    qq->length >= qq->max_length ? 0 :
	    qq->max_length - qq->length;
	if (space_left == 0)
		return (0);

	npop = ring_buffer__consume_n(nqq->ringbuf, space_left);

	return (npop < 0 ? -1 : npop);
}

/*
 * The counters of the blocks. A block is not a loop over its lines, so a
 * line has no counter: the denials of a block are the hits of its first
 * line, and evals stay 0.
 */
static int
nova_queue_update_block_stats(struct quark_queue *qq, int num_cpus)
{
	struct nova_queue	*nqq = block_nova_queue(qq);
	struct nova		*nova;
	struct quark_rule	*qr;
	struct nova_block_stats	*st;
	u64			*denied;
	size_t			 i;
	u32			 block, zero = 0;
	int			 j, r = -1;

	if (nqq == NULL || nqq->blocks == NULL)
		return (0);
	nova = nqq->nova;
	denied = calloc(num_cpus, sizeof(*denied));
	st = calloc(num_cpus, sizeof(*st));
	if (denied == NULL || st == NULL) {
		qwarn("calloc");
		goto done;
	}

	/* Blocks are numbered in the order of the ruleset */
	for (i = 0, block = 0; i < qq->ruleset->n_rules; ) {
		qr = qq->ruleset->rules + i;
		if (qr->action != QUARK_RA_BLOCK_ON &&
		    qr->action != QUARK_RA_BLOCK_EXCEPT) {
			i++;
			continue;
		}
		if (bpf_map__lookup_elem(nova->maps.blk_denied, &block,
		    sizeof(block), denied, sizeof(*denied) * num_cpus,
		    0) != 0) {
			qwarn("bpf_map__lookup_elem");
			goto done;
		}
		qr->hits = 0;
		for (j = 0; j < num_cpus; j++)
			qr->hits += denied[j];
		block++;
		i = qr->skip_to;
	}

	if (bpf_map__lookup_elem(nova->maps.blk_stats, &zero, sizeof(zero),
	    st, sizeof(*st) * num_cpus, 0) != 0) {
		qwarn("bpf_map__lookup_elem");
		goto done;
	}
	qq->stats.block_no_path = 0;
	qq->stats.block_lost = 0;
	qq->stats.block_no_slot = 0;
	for (j = 0; j < num_cpus; j++) {
		qq->stats.block_no_path += st[j].no_path;
		qq->stats.block_lost += st[j].lost;
		qq->stats.block_no_slot += st[j].no_slot;
	}
	r = 0;
done:
	free(denied);
	free(st);

	return (r);
}

static int
nova_queue_update_stats(struct quark_queue *qq)
{
	struct nova_queue	*nqq  = qq->queue_be;
	struct nova		*nova = nqq->nova;
	struct nova_rule_pcpu	*rule_pcpu;
	int			 num_cpus;
	struct quark_rule	*qr;
	u32			 i;
	int			 j;

	if (qq->ruleset == NULL)
		return (0);

	if ((num_cpus = libbpf_num_possible_cpus()) <= 0) {
		qwarnx("bad libbpf_num_possible_cpus: %d", num_cpus);
		return (-1);
	}
	if ((rule_pcpu = calloc(num_cpus, sizeof(*rule_pcpu))) == NULL) {
		qwarn("calloc");
		return (-1);
	}
#ifdef HAVE_STATIC_ASSERT
	static_assert(sizeof(*rule_pcpu) % 8 == 0,
	    "struct nova_rule_pcpu must be 8 byte aligned");
#endif

	for (i = 0; i < (u32)qq->ruleset->n_rules; i++) {
		qr = qq->ruleset->rules + i;

		if (bpf_map__lookup_elem(nova->maps.ruleset_pcpu, &i,
		    sizeof(i), rule_pcpu, sizeof(*rule_pcpu) * num_cpus, 0) != 0) {
			qwarn("bpf_map__lookup_elem");
			goto fail;
		}

		qr->evals = 0;
		qr->hits = 0;

		for (j = 0; j < num_cpus; j++) {
			qr->evals += rule_pcpu[j].evals;
			qr->hits += rule_pcpu[j].hits;
		}
	}

	free(rule_pcpu);

	return (nova_queue_update_block_stats(qq, num_cpus));
fail:
	free(rule_pcpu);

	return (-1);
}

/*
 * The key of a container in the kernel: the id that a hook finds in the
 * name of a cgroup, see blk_parse_cgroup() in nova.bpf.c. container_id is
 * <runtime>://<id>. Returns -1 for an id that a hook can't find, one that
 * is not 1 to NOVA_CONTAINER_IDLEN lowercase hex characters.
 */
static int
container_cid(const char *container_id, struct nova_block_cid *cid)
{
	const char	*id;
	size_t		 i, len;

	if ((id = strstr(container_id, "://")) != NULL)
		id += 3;
	else
		id = container_id;
	len = strlen(id);
	if (len == 0 || len > sizeof(cid->id))
		return (-1);
	for (i = 0; i < len; i++) {
		if (!((id[i] >= '0' && id[i] <= '9') ||
		    (id[i] >= 'a' && id[i] <= 'f')))
			return (-1);
	}
	bzero(cid, sizeof(*cid));
	memcpy(cid->id, id, len);

	return (0);
}

/*
 * Keep the lines of the blocks that the container fields of a container
 * allow, for the hooks. A container without an entry has the lines
 * without container fields, so that is not stored: most containers match
 * no container field of a block and take no room in the map.
 */
static void
nova_queue_container(struct quark_queue *qq,
    const struct quark_container *container, int removed)
{
	struct nova_queue	*nqq = block_nova_queue(qq);
	struct bpf_map		*map;
	struct nova_block_cid	 cid;
	u64			 lines;

	/* The backend is closed before the containers are freed */
	if (nqq == NULL || nqq->nova == NULL || nqq->blocks == NULL)
		return;
	if (container_cid(container->container_id, &cid) == -1)
		return;
	map = nqq->nova->maps.blk_container;
	lines = nqq->blocks->dc_container;
	if (!removed)
		lines = quark_block_container_bits(nqq->blocks, container);
	if (lines == nqq->blocks->dc_container) {
		if (bpf_map__delete_elem(map, &cid, sizeof(cid), 0) != 0 &&
		    errno != ENOENT)
			qwarn("can't forget container %s",
			    container->container_id);
		return;
	}
	/* The blocks then see a container without metadata */
	if (bpf_map__update_elem(map, &cid, sizeof(cid),
	    &lines, sizeof(lines), BPF_ANY) != 0)
		qwarn("can't store the block lines of container %s",
		    container->container_id);
}

/*
 * The enforcer: the blocks of the ruleset, enforced by the LSM programs
 * of nova next to a backend that can't deny, the EBPF one. That backend
 * delivers the events and userspace evaluates the other rules on them,
 * nova only denies. Nothing is loaded for a ruleset without blocks.
 * Returns -1 with errno set, ENOTSUP where blocks can't work: no BPF LSM,
 * or a kernel before Linux 5.17.
 */
int
nova_enforcer_open(struct quark_queue *qq)
{
	struct nova_queue	*nqq;

	if (qq->ruleset == NULL || qq->ruleset->n_blocks == 0)
		return (0);
	setup_libbpf_logs();
	if (check_bpf_lsm() == -1)
		return (-1);
	if ((nqq = calloc(1, sizeof(*nqq))) == NULL)
		return (-1);
	qq->enforcer = nqq;
	if ((nqq->nova = nova_open_object()) == NULL)
		goto fail;
	if (load_block_rodata(nqq, qq->ruleset,
	    (qq->flags & QQ_BLOCK_HOST) != 0) == -1)
		goto fail;
	if (nova_blocks_only(nqq, 1) == -1)
		goto fail;
	if (nova__load(nqq->nova) != 0) {
		qwarn("can't load the programs of the blocks, "
		    "they need Linux 5.17");
		goto unsupported;
	}
	if (load_blocks(nqq) == -1)
		goto fail;
	if (deny_ringbuf_setup(qq, nqq) == -1)
		goto fail;
	if (attach_blocks(nqq) == -1)
		goto unsupported;

	return (0);

unsupported:
	/* Not ours to judge when we may not, or can not, load anything */
	if (errno != EPERM && errno != EACCES && errno != ENOMEM)
		errno = ENOTSUP;
fail:
	nova_enforcer_close(qq);

	return (-1);
}

void
nova_enforcer_close(struct quark_queue *qq)
{
	struct nova_queue	*nqq = qq->enforcer;
	int			 saved_errno = errno;

	if (nqq == NULL)
		return;
	deny_ringbuf_close(qq, nqq);
	if (nqq->nova != NULL)
		nova__destroy(nqq->nova);
	quark_block_free(nqq->blocks);
	free(nqq);
	qq->enforcer = NULL;
	errno = saved_errno;
}


int
nova_enforcer_update_stats(struct quark_queue *qq)
{
	int	num_cpus;

	if ((num_cpus = libbpf_num_possible_cpus()) <= 0)
		return (-1);

	return (nova_queue_update_block_stats(qq, num_cpus));
}

void
nova_enforcer_container(struct quark_queue *qq,
    const struct quark_container *container, int removed)
{
	nova_queue_container(qq, container, removed);
}

static void
nova_queue_close(struct quark_queue *qq)
{
	struct nova_queue	*nqq = qq->queue_be;

	if (nqq == NULL)
		return;
	deny_ringbuf_close(qq, nqq);
	if (nqq->nova != NULL) {
		nova__destroy(nqq->nova);
		nqq->nova = NULL;
	}
	quark_block_free(nqq->blocks);
	nqq->blocks = NULL;

	if (nqq->ringbuf != NULL) {
		int	ringbuf_fd;

		ringbuf_fd = ring_buffer__epoll_fd(nqq->ringbuf);
		if (ringbuf_fd >= 0) {
			if (epoll_ctl(qq->epollfd, EPOLL_CTL_DEL, ringbuf_fd,
			    NULL) == -1)
				qwarn("epoll_ctl EPOLL_CTL_DEL");
		}

		/* this closes ringbuf_fd! */
		ring_buffer__free(nqq->ringbuf);
		nqq->ringbuf = NULL;
	}

	free(nqq);
	qq->queue_be = NULL;
}
