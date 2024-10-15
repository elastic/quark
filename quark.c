// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <sys/epoll.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "quark.h"

#define AGE(_ts, _now) 		((_ts) > (_now) ? 0 : (_now) - (_ts))

static int	raw_event_by_time_cmp(struct raw_event *, struct raw_event *);
static int	raw_event_by_pidtime_cmp(struct raw_event *, struct raw_event *);
static int	process_by_pid_cmp(struct quark_process *, struct quark_process *);

/* For debugging */
int	quark_verbose;

RB_PROTOTYPE(process_by_pid, quark_process,
    entry_by_pid, process_by_pid_cmp);
RB_GENERATE(process_by_pid, quark_process,
    entry_by_pid, process_by_pid_cmp);

RB_PROTOTYPE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);
RB_GENERATE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);

RB_PROTOTYPE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);
RB_GENERATE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);

struct quark {
	unsigned int	hz;
	u64		boottime;
} quark;

struct raw_event *
raw_event_alloc(int type)
{
	struct raw_event *raw;

	if ((raw = calloc(1, sizeof(*raw))) == NULL)
		return (NULL);

	raw->type = type;
	TAILQ_INIT(&raw->agg_queue);

	switch (raw->type) {
	case RAW_WAKE_UP_NEW_TASK: /* FALLTHROUGH */
	case RAW_EXIT_THREAD:
		raw->task.exit_code = -1;
		qstr_init(&raw->task.cwd);
		break;
	case RAW_EXEC:
		qstr_init(&raw->exec.filename);
		qstr_init(&raw->exec.ext.args);
		qstr_init(&raw->exec.ext.task.cwd);
		break;
	case RAW_EXEC_CONNECTOR:
		qstr_init(&raw->exec_connector.args);
		qstr_init(&raw->exec_connector.task.cwd);
		break;
	case RAW_COMM:		/* nada */
		break;
	default:
		qwarnx("unhandled raw_type %d", raw->type);
		free(raw);
		return (NULL);
	}

	return (raw);
}

void
raw_event_free(struct raw_event *raw)
{
	struct raw_event *aux;

	switch (raw->type) {
	case RAW_WAKE_UP_NEW_TASK:
	case RAW_EXIT_THREAD:
		qstr_free(&raw->task.cwd);
		break;
	case RAW_EXEC:
		qstr_free(&raw->exec.filename);
		qstr_free(&raw->exec.ext.task.cwd);
		qstr_free(&raw->exec.ext.args);
		break;
	case RAW_EXEC_CONNECTOR:
		qstr_free(&raw->exec_connector.args);
		qstr_free(&raw->exec_connector.task.cwd);
		break;
	case RAW_COMM:		/* nada */
		break;
	default:
		qwarnx("unhandled raw_type %d", raw->type);
		break;
	}

	while ((aux = TAILQ_FIRST(&raw->agg_queue)) != NULL) {
		TAILQ_REMOVE(&raw->agg_queue, aux, agg_entry);
		raw_event_free(aux);
	}

	free(raw);
}

static int
raw_event_by_time_cmp(struct raw_event *a, struct raw_event *b)
{
	if (a->time < b->time)
		return (-1);
	else
		return (a->time > b->time);
}

static int
raw_event_by_pidtime_cmp(struct raw_event *a, struct raw_event *b)
{
	if (a->pid < b->pid)
		return (-1);
	else if (a->pid > b->pid)
		return (1);

	if (a->time < b->time)
		return (-1);
	else
		return (a->time > b->time);
}

static inline u64
now64(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		err(1, "clock_gettime");

	return ((u64)ts.tv_sec * (u64)NS_PER_S + (u64)ts.tv_nsec);
}

static inline u64
raw_event_age(struct raw_event *raw, u64 now)
{
	return AGE(raw->time, now);
}

/*
 * Target age is the duration in ns of how long should we hold the event in the
 * tree before processing it. It's a function of the number of items in the tree
 * and its maximum capacity:
 * from [0; 10%]    -> 1000ms
 * from [90%; 100%] -> 0ms
 * from (10%; 90%)  -> linear from 1000ms -> 100ms
 */
static u64
raw_event_target_age(struct quark_queue *qq)
{
	int	v;

	if (qq->length < (qq->max_length / 10))
		v = qq->hold_time;
	else if (qq->length < ((qq->max_length / 10) * 9)) {
		v = qq->hold_time -
		    (qq->length / (qq->max_length / qq->hold_time)) + 1;
	} else
		v = 0;

	return ((u64)MS_TO_NS(v));
}

static inline int
raw_event_expired(struct quark_queue *qq, struct raw_event *raw, u64 now)
{
	u64	target;

	target = raw_event_target_age(qq);
	return (raw_event_age(raw, now) >= target);
}

/*
 * Insert without a colision, cheat on the timestamp in case we do. NOTE: since
 * we bump "time" here, we shouldn't copy "time" before it sits in the tree.
 */
void
raw_event_insert(struct quark_queue *qq, struct raw_event *raw)
{
	struct raw_event	*col;
	int			 attempts = 10;

	/*
	 * Link it first by time
	 */
	do {
		col = RB_INSERT(raw_event_by_time, &qq->raw_event_by_time, raw);
		if (likely(col == NULL))
			break;

		/*
		 * We managed to get a collision on the TSC, this happens!
		 * We just bump time by one until we can insert it.
		 */
		raw->time++;
		qwarnx("raw_event_by_time collision");
	} while (--attempts > 0);

	if (unlikely(col != NULL))
		err(1, "we got consecutive collisions, this is a bug");

	/*
	 * Link it in the combined tree, we accept no collisions here as the
	 * above case already saves us, but trust nothing.
	 */
	/* XXX this should be by tid, but we're not there yet XXX */
	col = RB_INSERT(raw_event_by_pidtime, &qq->raw_event_by_pidtime, raw);
	if (unlikely(col != NULL))
		err(1, "collision on pidtime tree, this is a bug");

	/* if (qq->min == NULL || raw_event_by_time_cmp(raw, qq->min) == -1) */
	/* 	qq->min = raw; */
	qq->length++;
	qq->stats.insertions++;
}

static void
raw_event_remove(struct quark_queue *qq, struct raw_event *raw)
{
	RB_REMOVE(raw_event_by_time, &qq->raw_event_by_time, raw);
	RB_REMOVE(raw_event_by_pidtime, &qq->raw_event_by_pidtime, raw);
	/* if (qq->min == raw) qq->min = NULL */
	qq->length--;
	qq->stats.removals++;
}

static int
tty_type(int major, int minor)
{
	if (major >= 136 && major <= 143)
		return (QUARK_TTY_PTS);

	if (major == 4) {
		if (minor <= 63)
			return (QUARK_TTY_CONSOLE);
		else if (minor <= 255)
			return (QUARK_TTY_TTY);
	}

	return (QUARK_TTY_UNKNOWN);
}

#if 0
static void
event_copy_fields(struct quark_process *dst, struct quark_process *src)
{
	char	*p;
	u_int	 i;

#define MCPY(_f, _l)						\
	do {							\
		memcpy(dst->_f, src->_f, src->_l);		\
		for (i = 0; i < src->_l; i++) {			\
			p = (char *)dst->_f + i;		\
			if (*p == 0)				\
				continue;			\
			if (!isprint(*p))			\
				*p = '?';			\
		}						\
	} while (0)

#define STCPY(_f)						\
	do {							\
		strlcpy(dst->_f, src->_f, sizeof(dst->_f));	\
		for (p = dst->_f; *p != 0; p++)	{		\
			if (!isprint(*p))			\
				*p = '?';			\
		}						\
	} while (0)

#define CPY(_f)		dst->_f = src->_f

	CPY(flags);

	if (src->flags & QUARK_F_PROC) {
		CPY(proc_cap_inheritable);
		CPY(proc_cap_permitted);
		CPY(proc_cap_effective);
		CPY(proc_cap_bset);
		CPY(proc_cap_ambient);
		CPY(proc_time_boot);
		CPY(proc_ppid);
		CPY(proc_uid);
		CPY(proc_gid);
		CPY(proc_suid);
		CPY(proc_sgid);
		CPY(proc_euid);
		CPY(proc_egid);
		CPY(proc_pgid);
		CPY(proc_sid);
		CPY(proc_tty_major);
		CPY(proc_tty_minor);
		CPY(proc_entry_leader_type);
		CPY(proc_entry_leader);
	}
	if (src->flags & QUARK_F_EXIT) {
		CPY(exit_code);
		CPY(exit_time_event);
	}
	if (src->flags & QUARK_F_COMM)
		STCPY(comm);
	if (src->flags & QUARK_F_FILENAME)
		STCPY(filename);
	if (src->flags & QUARK_F_CMDLINE) {
		CPY(cmdline_len);
		MCPY(cmdline, cmdline_len);
	}
	if (src->flags & QUARK_F_CWD)
		STCPY(cwd);

#undef CPY
#undef STCPY
#undef MCPY
}

static void
event_copy_out(struct quark_process *dst, struct quark_process *src, u64 events)
{
	bzero(&dst->quark_process_zero_start,
	    (char *)&dst->quark_process_zero_end - (char *)&dst->quark_process_zero_start);
	dst->pid = src->pid;
	event_copy_fields(dst, src);
}
#endif
static struct quark_process *
process_cache_get(struct quark_queue *qq, int pid, int alloc)
{
	struct quark_process	 key;
	struct quark_process	*qp;

	key.pid = pid;
	qp = RB_FIND(process_by_pid, &qq->process_by_pid, &key);
	if (qp != NULL)
		return (qp);

	if (!alloc) {
		errno = ESRCH;
		return (NULL);
	}

	qp = calloc(1, sizeof(*qp));
	if (qp == NULL)
		return (NULL);
	qp->pid = pid;
	if (RB_INSERT(process_by_pid, &qq->process_by_pid, qp) != NULL) {
		qwarnx("collision, this is a bug");
		free(qp);
		return (NULL);
	}

	return (qp);
}

static void
process_cache_inherit(struct quark_queue *qq, struct quark_process *qp, int ppid)
{
	struct quark_process	*parent;

	if ((parent = process_cache_get(qq, ppid, 0)) == NULL)
		return;

	/* Ignore QUARK_F_PROC? as we always have it all on fork */

	if (parent->flags & QUARK_F_COMM) {
		qp->flags |= QUARK_F_COMM;
		strlcpy(qp->comm, parent->comm, sizeof(qp->comm));
	}
	if (parent->flags & QUARK_F_FILENAME) {
		qp->flags |= QUARK_F_FILENAME;
		strlcpy(qp->filename, parent->filename, sizeof(qp->filename));
	}
	/* Do we really want CMDLINE? */
	if (parent->flags & QUARK_F_CMDLINE) {
		qp->flags |= QUARK_F_CMDLINE;
		qp->cmdline_len = parent->cmdline_len;
		memcpy(qp->cmdline, parent->cmdline, parent->cmdline_len);
	}
}

static void
process_cache_delete(struct quark_queue *qq, struct quark_process *qp)
{
	RB_REMOVE(process_by_pid, &qq->process_by_pid, qp);
	if (qp->gc_time)
		TAILQ_REMOVE(&qq->event_gc, qp, entry_gc);
	free(qp);
}

static int
process_cache_gc(struct quark_queue *qq)
{
	struct quark_process	*qp;
	u64			 now;
	int			 n;

	now = now64();
	n = 0;
	while ((qp = TAILQ_FIRST(&qq->event_gc)) != NULL) {
		if (AGE(qp->gc_time, now) < qq->cache_grace_time)
			break;
		process_cache_delete(qq, qp);
		n++;
	}

	return (n);
}

static int
process_by_pid_cmp(struct quark_process *a, struct quark_process *b)
{
	if (a->pid < b->pid)
		return (-1);
	else if (a->pid > b->pid)
		return (1);

	return (0);
}

static const char *
event_flag_str(u64 flag)
{
	switch (flag) {
	case QUARK_F_PROC:
		return "PROC";
	case QUARK_F_EXIT:
		return "EXIT";
	case QUARK_F_COMM:
		return "COMM";
	case QUARK_F_FILENAME:
		return "FILENAME";
	case QUARK_F_CMDLINE:
		return "CMDLINE";
	case QUARK_F_CWD:
		return "CWD";
	default:
		return "?";
	}
}

static const char *
event_type_str(u64 event)
{
	switch (event) {
	case QUARK_EV_FORK:
		return "FORK";
	case QUARK_EV_EXEC:
		return "EXEC";
	case QUARK_EV_EXIT:
		return "EXIT";
	case QUARK_EV_SETPROCTITLE:
		return "SETPROCTITLE";
	case QUARK_EV_SNAPSHOT:
		return "SNAPSHOT";
	default:
		return "?";
	}
}

static int
events_type_str(u64 events, char *buf, size_t len)
{
	int	i, n;
	u64	ev;

	if (len == 0)
		return (-1);

	for (i = 0, n = 0, *buf = 0; i < 64; i++) {
		ev = (u64)1 << i;
		if ((events & ev) == 0)
			continue;
		if (n > 0)
			if (strlcat(buf, "+", len) >= len)
				return (-1);
		if (strlcat(buf, event_type_str(ev), len) >= len)
			return (-1);
		n++;
	}

	return (0);
}

static int
entry_leader_compute(struct quark_queue *qq, struct quark_process *qp)
{
	struct quark_process	*parent;
	char			*basename, *p_basename;
	int			 tty;
	int			 is_ses_leader;

	if ((qq->flags & QQ_ENTRY_LEADER) == 0)
		return (0);

	/*
	 * Init
	 */
	if (qp->pid == 1) {
		qp->proc_entry_leader_type = QUARK_ELT_INIT;
		qp->proc_entry_leader = 1;

		return (0);

	}

	is_ses_leader = qp->pid == qp->proc_sid;

	/*
	 * All kthreads are QUARK_ELT_KTHREAD;
	 */
	if (qp->pid == 2 || qp->proc_ppid == 2) {
		qp->proc_entry_leader_type = QUARK_ELT_KTHREAD;
		qp->proc_entry_leader = is_ses_leader ? qp->pid : 2;

		return (0);
	}

	tty = tty_type(qp->proc_tty_major, qp->proc_tty_minor);

	basename = strrchr(qp->filename, '/');
	if (basename == NULL)
		basename = "";
	else
		basename++;

	/*
	 * CONSOLE only considers the login process, keep the same behaviour
	 * from other elastic products.
	 */
	if (is_ses_leader) {
		if (tty == QUARK_TTY_TTY) {
			qp->proc_entry_leader_type = QUARK_ELT_TERM;
			qp->proc_entry_leader = qp->pid;

			return (0);
		}

		if (tty == QUARK_TTY_CONSOLE && !strcmp(basename, "login")) {
			qp->proc_entry_leader_type = QUARK_ELT_TERM;
			qp->proc_entry_leader = qp->pid;

			return (0);
		}
	}

	/*
	 * Fetch the parent
	 */
	parent = process_cache_get(qq, qp->proc_ppid, 0);
	if (parent == NULL || parent->proc_entry_leader_type == QUARK_ELT_UNKNOWN)
		return (-1);

	/*
	 * Since we didn't hit anything, inherit from parent. Non leaders are
	 * done.
	 */
	qp->proc_entry_leader_type = parent->proc_entry_leader_type;
	qp->proc_entry_leader = parent->proc_entry_leader;
	if (!is_ses_leader)
		return (0);

#define STARTS_WITH(_x, _y) (!strncmp(_x, _y, strlen(_y)))
	/*
	 * Filter these out, keep same behaviour of other elastic products.
	 */
	if (STARTS_WITH(basename, "runc") ||
	    STARTS_WITH(basename, "containerd-shim") ||
	    STARTS_WITH(basename, "calico-node") ||
	    STARTS_WITH(basename, "check-status") ||
	    STARTS_WITH(basename, "pause") ||
	    STARTS_WITH(basename, "conmon"))
		return (0);

	p_basename = strrchr(parent->filename, '/');
	if (p_basename == NULL)
		p_basename = "";
	else
		p_basename++;

	/*
	 * SSM.
	 */
	if (tty == QUARK_TTY_PTS &&
	    !strcmp(p_basename, "ssm-session-worker")) {
		qp->proc_entry_leader_type = QUARK_ELT_SSM;
		qp->proc_entry_leader = qp->pid;

		return (0);
	}

	/*
	 * SSHD. If we're a direct descendant of sshd, but we're not sshd
	 * ourselves: we're an entry group leader for sshd.
	 */
	if (!strcmp(p_basename, "sshd") && strcmp(basename, "sshd")) {
		qp->proc_entry_leader_type = QUARK_ELT_SSHD;
		qp->proc_entry_leader = qp->pid;

		return (0);
	}

	/*
	 * Container. Similar dance to sshd but more names, cloud-defend ignores
	 * basename here.
	 */
	if (STARTS_WITH(p_basename, "containerd-shim") ||
	    STARTS_WITH(p_basename, "runc") ||
	    STARTS_WITH(p_basename, "conmon")) {
		qp->proc_entry_leader_type = QUARK_ELT_CONTAINER;
		qp->proc_entry_leader = qp->pid;

		return (0);
	}
#undef STARTS_WITH

	if (qp->proc_entry_leader == QUARK_ELT_UNKNOWN)
		qwarnx("%d (%s) is UNKNOWN (tty=%d)",
		    qp->pid, qp->filename, tty);

	return (0);
}

struct proc_node {
	u32			pid;
	TAILQ_ENTRY(proc_node)	entry;
};

TAILQ_HEAD(proc_node_list, proc_node);

static int
entry_leader_build_walklist(struct quark_queue *qq, struct proc_node_list *list)
{
	struct proc_node	*node, *new_node;
	struct quark_process	*qp;

	TAILQ_INIT(list);

	/*
	 * Look for the root nodes, this is init(pid = 1) and kthread(pid = 2),
	 * but maybe there's something else in the future or in the past so
	 * don't hardcode.
	 */

	RB_FOREACH(qp, process_by_pid, &qq->process_by_pid) {
		if (qp->proc_ppid != 0)
			continue;

		new_node = calloc(1, sizeof(*new_node));
		if (new_node == NULL)
			goto fail;
		new_node->pid = qp->pid;
		TAILQ_INSERT_TAIL(list, new_node, entry);
	}

	/*
	 * Now do the "recursion"
	 */
	TAILQ_FOREACH(node, list, entry) {
		RB_FOREACH(qp, process_by_pid, &qq->process_by_pid) {
			if (qp->proc_ppid != node->pid)
				continue;

			new_node = calloc(1, sizeof(*new_node));
			if (new_node == NULL)
				goto fail;
			new_node->pid = qp->pid;
			TAILQ_INSERT_TAIL(list, new_node, entry);
		}
	}

	return (0);

fail:
	while ((node = TAILQ_FIRST(list)) != NULL) {
		TAILQ_REMOVE(list, node, entry);
		free(node);
	}

	return (-1);
}

static int
entry_leaders_build(struct quark_queue *qq)
{
	struct quark_process	*qp;
	struct proc_node	*node;
	struct proc_node_list	 list;

	if ((qq->flags & QQ_ENTRY_LEADER) == 0)
		return (0);

	if (entry_leader_build_walklist(qq, &list) == -1)
		return (-1);

	while ((node = TAILQ_FIRST(&list)) != NULL) {
		qp = process_cache_get(qq, node->pid, 0);
		if (qp == NULL)
			goto fail;
		if (entry_leader_compute(qq, qp) == -1)
			qwarnx("unknown entry_leader for pid %d", qp->pid);
		TAILQ_REMOVE(&list, node, entry);
		free(node);
	}

	return (0);

fail:
	while ((node = TAILQ_FIRST(&list)) != NULL) {
		TAILQ_REMOVE(&list, node, entry);
		free(node);
	}

	return (-1);
}

static const char *
entry_leader_type_str(u32 entry_leader_type)
{
	switch (entry_leader_type) {
	case QUARK_ELT_UNKNOWN:
		return "UNKNOWN";
	case QUARK_ELT_INIT:
		return "INIT";
	case QUARK_ELT_KTHREAD:
		return "KTHREAD";
	case QUARK_ELT_SSHD:
		return "SSHD";
	case QUARK_ELT_SSM:
		return "SSM";
	case QUARK_ELT_CONTAINER:
		return "CONTAINER";
	case QUARK_ELT_TERM:
		return "TERM";
	case QUARK_ELT_CONSOLE:
		return "CONSOLE";
	default:
		return "?";
	}
}

#define P(...)						\
	do {						\
		if (fprintf(f, __VA_ARGS__) < 0)	\
			return (-1);			\
	} while(0)
int
quark_event_dump(struct quark_event *qev, FILE *f)
{
	const char			*flagname;
	char				 events[1024];
	const struct quark_process	*qp;

	qp = qev->process;
	if (qp == NULL)
		return (-1);

	/* TODO: add tid */
	events_type_str(qev->events, events, sizeof(events));
	P("->%d (%s)\n", qp->pid, events);
	if (qp->flags & QUARK_F_COMM) {
		flagname = event_flag_str(QUARK_F_COMM);
		P("  %.4s\tcomm=%s\n", flagname, qp->comm);
	}
	if (qp->flags & QUARK_F_CMDLINE) {
		int		 i;
		struct args	*args;

		flagname = event_flag_str(QUARK_F_CMDLINE);

		P("  %.4s\tcmdline=", flagname);
		P("[ ");
		args = args_make(qp);
		if (args == NULL)
			P("(%s)", strerror(errno));
		else {
			for (i = 0; i < args->argc; i++) {
				if (i > 0)
					P(", ");
				P("%s", args->argv[i]);
			}
			args_free(args);
		}
		P(" ]\n");
	}
	if (qp->flags & QUARK_F_PROC) {
		flagname = event_flag_str(QUARK_F_PROC);
		P("  %.4s\tppid=%d\n", flagname, qp->proc_ppid);
		P("  %.4s\tuid=%d gid=%d suid=%d sgid=%d "
		    "euid=%d egid=%d pgid=%d sid=%d\n",
		    flagname, qp->proc_uid, qp->proc_gid, qp->proc_suid,
		    qp->proc_sgid, qp->proc_euid, qp->proc_egid,
		    qp->proc_pgid, qp->proc_sid);
		P("  %.4s\tcap_inheritable=0x%llx cap_permitted=0x%llx "
		    "cap_effective=0x%llx\n",
		    flagname, qp->proc_cap_inheritable,
		    qp->proc_cap_permitted, qp->proc_cap_effective);
		P("  %.4s\tcap_bset=0x%llx cap_ambient=0x%llx\n",
		    flagname, qp->proc_cap_bset, qp->proc_cap_ambient);
		P("  %.4s\ttime_boot=%llu tty_major=%d tty_minor=%d\n",
		    flagname, qp->proc_time_boot,
		    qp->proc_tty_major, qp->proc_tty_minor);
		P("  %.4s\tentry_leader_type=%s entry_leader=%d\n", flagname,
		    entry_leader_type_str(qp->proc_entry_leader_type),
		    qp->proc_entry_leader);
	}
	if (qp->flags & QUARK_F_CWD) {
		flagname = event_flag_str(QUARK_F_CWD);
		P("  %.4s\tcwd=%s\n", flagname, qp->cwd);
	}
	if (qp->flags & QUARK_F_FILENAME) {
		flagname = event_flag_str(QUARK_F_FILENAME);
		P("  %.4s\tfilename=%s\n", flagname, qp->filename);
	}
	if (qp->flags & QUARK_F_EXIT) {
		flagname = event_flag_str(QUARK_F_EXIT);
		P("  %.4s\texit_code=%d exit_time=%llu\n", flagname,
		    qp->exit_code, qp->exit_time_event);
	}

	fflush(f);

	return (0);
}
#undef P

/* User facing version of process_cache_lookup() */
const struct quark_process *
quark_process_lookup(struct quark_queue *qq, int pid)
{
	return (process_cache_get(qq, pid, 0));
}

void
quark_process_iter_init(struct quark_process_iter *qi, struct quark_queue *qq)
{
	qi->qq = qq;
	qi->qp = RB_MIN(process_by_pid, &qq->process_by_pid);
}

const struct quark_process *
quark_process_iter_next(struct quark_process_iter *qi)
{
	const struct quark_process	*qp;

	qp = qi->qp;
	if (qi->qp != NULL)
		qi->qp = RB_NEXT(process_by_pid, &qq->process_by_pid, qi->qp);

	return (qp);
}

static int
raw_event_process(struct quark_queue *qq, struct raw_event *src, struct
    quark_event *dst)
{
	struct quark_process		*qp;
	struct raw_event                *agg;
	struct raw_task                 *raw_fork, *raw_exit, *raw_task;
	struct raw_comm                 *raw_comm;
	struct raw_exec                 *raw_exec;
	struct raw_exec_connector       *raw_exec_connector;
	char				*comm;
	char				*cwd;
	char				*args;
	size_t				 args_len;
	u64				 events;

	raw_fork = NULL;
	raw_exit = NULL;
	raw_task = NULL;
	raw_comm = NULL;
	raw_exec = NULL;
	raw_exec_connector = NULL;
	comm = NULL;
	cwd = NULL;
	args = NULL;
	args_len = 0;

	/* XXX pass if this is a fork down, so we can evict the old one XXX */
	qp = process_cache_get(qq, src->pid, 1);
	if (qp == NULL)
		return (-1);

	events = 0;

	switch (src->type) {
	case RAW_WAKE_UP_NEW_TASK:
		events |= QUARK_EV_FORK;
		raw_fork = &src->task;
		break;
	case RAW_EXEC:
		events |= QUARK_EV_EXEC;
		raw_exec = &src->exec;
		break;
	case RAW_EXIT_THREAD:
		events |= QUARK_EV_EXIT;
		raw_exit = &src->task;
		break;
	case RAW_COMM:
		events |= QUARK_EV_SETPROCTITLE;
		raw_comm = &src->comm;
		break;
	case RAW_EXEC_CONNECTOR:
		events |= QUARK_EV_EXEC;
		raw_exec_connector = &src->exec_connector;
		break;
	default:
		return (errno = EINVAL, -1);
		break;		/* NOTREACHED */
	};

	TAILQ_FOREACH(agg, &src->agg_queue, agg_entry) {
		switch (agg->type) {
		case RAW_WAKE_UP_NEW_TASK:
			raw_fork = &agg->task;
			events |= QUARK_EV_FORK;
			break;
		case RAW_EXEC:
			events |= QUARK_EV_EXEC;
			raw_exec = &agg->exec;
			break;
		case RAW_EXIT_THREAD:
			events |= QUARK_EV_EXIT;
			raw_exit = &agg->task;
			break;
		case RAW_COMM:
			events |= QUARK_EV_SETPROCTITLE;
			raw_comm = &agg->comm;
			break;
		case RAW_EXEC_CONNECTOR:
			events |= QUARK_EV_EXEC;
			raw_exec_connector = &agg->exec_connector;
			break;
		default:
			break;
		}
	}

	/* QUARK_F_PROC */
	if (raw_fork != NULL) {
		process_cache_inherit(qq, qp, raw_fork->ppid);
		raw_task = raw_fork;
		cwd = raw_task->cwd.p;
	}
	if (raw_exit != NULL) {
		qp->flags |= QUARK_F_EXIT;

		qp->exit_code = raw_exit->exit_code;
		if (raw_exit->exit_time_event)
			qp->exit_time_event = quark.boottime + raw_exit->exit_time_event;
		raw_task = raw_exit;
		/* cwd is invalid, don't collect */
		/* NOTE: maybe there are more things we _don't_ want from exit */
	}
	if (raw_exec != NULL) {
		qp->flags |= QUARK_F_FILENAME;

		strlcpy(qp->filename, raw_exec->filename.p, sizeof(qp->filename));
		if (raw_exec->flags & RAW_EXEC_F_EXT) {
			args = raw_exec->ext.args.p;
			args_len = raw_exec->ext.args_len;
			raw_task = &raw_exec->ext.task;
			cwd = raw_task->cwd.p;
		}
	}
	if (raw_exec_connector != NULL) {
		args = raw_exec_connector->args.p;
		args_len = raw_exec_connector->args_len;
		raw_task = &raw_exec_connector->task;
		cwd = raw_task->cwd.p;
	}
	if (raw_task != NULL) {
		qp->flags |= QUARK_F_PROC;

		qp->proc_cap_inheritable = raw_task->cap_inheritable;
		qp->proc_cap_permitted = raw_task->cap_permitted;
		qp->proc_cap_effective = raw_task->cap_effective;
		qp->proc_cap_bset = raw_task->cap_bset;
		qp->proc_cap_ambient = raw_task->cap_ambient;
		qp->proc_time_boot = quark.boottime + raw_task->start_boottime;
		qp->proc_ppid = raw_task->ppid;
		qp->proc_uid = raw_task->uid;
		qp->proc_gid = raw_task->gid;
		qp->proc_suid = raw_task->suid;
		qp->proc_sgid = raw_task->sgid;
		qp->proc_euid = raw_task->euid;
		qp->proc_egid = raw_task->egid;
		qp->proc_pgid = raw_task->pgid;
		qp->proc_sid = raw_task->sid;
		qp->proc_tty_major = raw_task->tty_major;
		qp->proc_tty_minor = raw_task->tty_minor;

		/* Don't set cwd as it's not valid on exit */
		comm = raw_task->comm;
	}
	if (raw_comm != NULL)
		comm = raw_comm->comm; /* raw_comm always overrides */
	/*
	 * Field pointer checking, stuff the block above sets so we save some
	 * code.
	 */
	if (args != NULL) {
		size_t		 copy_len;

		qp->flags |= QUARK_F_CMDLINE;

		qp->cmdline[0] = 0;
		copy_len = min(sizeof(qp->cmdline), args_len);
		if (copy_len > 0) {
			memcpy(qp->cmdline, args, copy_len);
			qp->cmdline[copy_len - 1] = 0;
		}
		qp->cmdline_len = copy_len;
	}
	if (comm != NULL) {
		qp->flags |= QUARK_F_COMM;

		strlcpy(qp->comm, comm, sizeof(qp->comm));
	}
	if (cwd != NULL) {
		qp->flags |= QUARK_F_CWD;

		strlcpy(qp->cwd, cwd, sizeof(qp->cwd));
	}

	if (qp->flags == 0)
		qwarnx("no flags");

	if (events & (QUARK_EV_FORK | QUARK_EV_EXEC)) {
		if (entry_leader_compute(qq, qp) == -1)
			qwarnx("unknown entry_leader for pid %d", qp->pid);
	}

	/*
	 * On the very unlikely case that pids get re-used, we might
	 * see an old qp for a new process, which could prompt us in
	 * trying to remove it twice. In other words, gc_time guards
	 * presence in the TAILQ.
	 */
	if (raw_exit != NULL && qp->gc_time == 0) {
		qp->gc_time = now64();
		TAILQ_INSERT_TAIL(&qq->event_gc, qp, entry_gc);
	}

	dst->events = events;
	dst->process = qp;

	return (0);
}

static int
sproc_status_line(struct quark_process *qp, const char *k, const char *v)
{
	const char		*errstr;

	if (*v == 0)
		return (0);

	if (!strcmp(k, "Pid")) {
		qp->pid = strtonum(v, 0, UINT32_MAX, &errstr);
		if (errstr != NULL)
			return (-1);
	} else if (!strcmp(k, "PPid")) {
		qp->proc_ppid = strtonum(v, 0, UINT32_MAX, &errstr);
		if (errstr != NULL)
			return (-1);
	} else if (!strcmp(k, "Uid")) {
		if (sscanf(v, "%d %d %d\n",
		    &qp->proc_uid, &qp->proc_euid, &qp->proc_suid) != 3)
			return (-1);
	} else if (!strcmp(k, "Gid")) {
		if (sscanf(v, "%d %d %d\n",
		    &qp->proc_gid, &qp->proc_egid, &qp->proc_sgid) != 3)
			return (-1);
	} else if (!strcmp(k, "CapInh")) {
		if (strtou64(&qp->proc_cap_inheritable, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapPrm")) {
		if (strtou64(&qp->proc_cap_permitted, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapEff")) {
		if (strtou64(&qp->proc_cap_effective, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapBnd")) {
		if (strtou64(&qp->proc_cap_bset, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapAmb")) {
		if (strtou64(&qp->proc_cap_ambient, v, 16) == -1)
			return (-1);
	}

	return (0);
}

static int
sproc_stat(struct quark_process *qp, int dfd)
{
	int			 fd, r, ret;
	char			*buf, *p;
	u32			 pgid, sid, tty;
	unsigned long long	 starttime;

	buf = NULL;
	ret = -1;

	if ((fd = openat(dfd, "stat", O_RDONLY)) == -1) {
		qwarn("open stat");
		return (-1);
	}
	buf = load_file_nostat(fd, NULL);
	if (buf == NULL)
		goto cleanup;

	/*
	 * comm might have spaces, newlines and whatnot, procfs is nice enough
	 * to put parenthesis around them.
	 */
	p = strrchr(buf, ')');
	if (p == NULL)
		goto cleanup;
	p++;			/* Skip over ") " */
	while (isspace(*p))
		p++;
	starttime = 0;
	r = sscanf(p,
	    "%*s "		/* (3) state */
	    "%*s "		/* (4) ppid */
	    "%d "		/* (5) pgrp */
	    "%d "		/* (6) session */
	    "%d "		/* (7) tty_nr */
	    "%*s "		/* (8) tpgid */
	    "%*s "		/* (9) flags */
	    "%*s "		/* (10) minflt */
	    "%*s "		/* (11) cminflt */
	    "%*s "		/* (12) majflt */
	    "%*s "		/* (13) cmajflt */
	    "%*s "		/* (14) utime */
	    "%*s "		/* (15) stime */
	    "%*s "		/* (16) cutime */
	    "%*s "		/* (17) cstime */
	    "%*s "		/* (18) priority */
	    "%*s "		/* (19) nice */
	    "%*s "		/* (20) num_threads */
	    "%*s "		/* (21) itrealvalue */
	    "%llu ",		/* (22) starttime */
				/* ... */
	    &pgid,
	    &sid,
	    &tty,
	    &starttime);

	if (r == 4) {
		qp->proc_pgid = pgid;
		qp->proc_sid = sid;
		/* See proc(5) */
		qp->proc_tty_major = (tty >> 8) & 0xff;
		qp->proc_tty_minor = ((tty >> 12) & 0xfff00) | (tty & 0xff);
		qp->proc_time_boot =
		    quark.boottime +
		    (((u64)starttime / (u64)quark.hz) * NS_PER_S);

		ret = 0;
	}

cleanup:
	free(buf);
	close(fd);

	return (ret);
}

static int
sproc_status(struct quark_process *qp, int dfd)
{
	int			 fd, ret;
	FILE			*f;
	ssize_t			 n;
	size_t			 line_len;
	char			*line, *k, *v;

	if ((fd = openat(dfd, "status", O_RDONLY)) == -1) {
		qwarn("open status");
		return (-1);
	}
	f = fdopen(fd, "r");
	if (f == NULL)
		return (-1);

	ret = 0;
	line_len = 0;
	line = NULL;
	while ((n = getline(&line, &line_len, f)) != -1) {
		/* k:\tv\n = 5 */
		if (n < 5 || line[n - 1] != '\n') {
			qwarnx("bad line");
			ret = -1;
			break;
		}
		line[n - 1] = 0;
		k = line;
		v = strstr(line, ":\t");
		if (v == NULL) {
			qwarnx("no `:\\t` found");
			ret = -1;
			break;
		}
		*v = 0;
		v += 2;
		if (sproc_status_line(qp, k, v) == -1) {
			qwarnx("can't handle %s", k);
			ret = -1;
			break;
		}
	}
	free(line);
	fclose(f);

	return (ret);

}

static int
sproc_cmdline(struct quark_process *qp, int dfd)
{
	int	 fd;
	char	*buf;
	size_t	 buf_len, copy_len;

	if ((fd = openat(dfd, "cmdline", O_RDONLY)) == -1) {
		qwarn("open cmdline");
		return (-1);
	}
	buf = load_file_nostat(fd, &buf_len);
	close(fd);
	if (buf == NULL)
		return (-1);
	copy_len = min(sizeof(qp->cmdline), buf_len);
	memcpy(qp->cmdline, buf, copy_len);
	free(buf);
	/* paranoia */
	qp->cmdline[copy_len - 1] = 0;
	qp->cmdline_len = copy_len;

	return (0);
}

static int
sproc_pid(struct quark_queue *qq, int pid, int dfd)
{
	struct quark_process	*qp;

	/*
	 * This allocates and inserts it into the cache in case it's not already
	 * there, if say, sproc_status() fails, process will be largely empty,
	 * still we know there was a process there somewhere.
	 */
	qp = process_cache_get(qq, pid, 1);
	if (qp == NULL)
		return (-1);

	if (sproc_status(qp, dfd) == 0 && sproc_stat(qp, dfd) == 0)
		qp->flags |= QUARK_F_PROC;

	/* QUARK_F_COMM */
	if (readlineat(dfd, "comm", qp->comm, sizeof(qp->comm)) > 0)
		qp->flags |= QUARK_F_COMM;
	/* QUARK_F_FILENAME */
	if (qreadlinkat(dfd, "exe", qp->filename, sizeof(qp->filename)) > 0)
		qp->flags |= QUARK_F_FILENAME;
	/* QUARK_F_CMDLINE */
	if (sproc_cmdline(qp, dfd) == 0)
		qp->flags |= QUARK_F_CMDLINE;
	/* QUARK_F_CWD */
	if (qreadlinkat(dfd, "cwd", qp->cwd, sizeof(qp->cwd)) > 0)
		qp->flags |= QUARK_F_CWD;

	return (0);
}

static int
sproc_scrape(struct quark_queue *qq)
{
	FTS	*tree;
	FTSENT	*f, *p;
	int	 dfd, rootfd;
	char	*argv[] = { "/proc", NULL };

	if ((tree = fts_open(argv, FTS_NOCHDIR, NULL)) == NULL)
		return (-1);
	if ((rootfd = open(argv[0], O_PATH)) == -1) {
		fts_close(tree);
		return (-1);
	}

	while ((f = fts_read(tree)) != NULL) {
		if (f->fts_info == FTS_ERR || f->fts_info == FTS_NS)
			qwarnx("%s: %s", f->fts_name, strerror(f->fts_errno));
		if (f->fts_info != FTS_D)
			continue;
		fts_set(tree, f, FTS_SKIP);

		if ((p = fts_children(tree, 0)) == NULL) {
			qwarn("fts_children");
			continue;
		}
		for (; p != NULL; p = p->fts_link) {
			int		 pid;
			const char	*errstr;

			if (p->fts_info == FTS_ERR || p->fts_info == FTS_NS) {
				qwarnx("%s: %s",
				    p->fts_name, strerror(p->fts_errno));
				continue;
			}
			if (p->fts_info != FTS_D || !isnumber(p->fts_name))
				continue;

			if ((dfd = openat(rootfd, p->fts_name, O_PATH)) == -1) {
				qwarn("openat %s", p->fts_name);
				continue;
			}
			pid = strtonum(p->fts_name, 1, UINT32_MAX, &errstr);
			if (errstr != NULL) {
				qwarnx("bad pid %s: %s", p->fts_name, errstr);
				goto next;
			}
			if (sproc_pid(qq, pid, dfd) == -1)
				qwarnx("can't scrape %s", p->fts_name);
next:
			close(dfd);
		}
	}

	close(rootfd);
	fts_close(tree);

	return (0);
}

static u64
fetch_boottime(void)
{
	char		*line;
	const char	*errstr, *needle;
	u64		 btime;

	needle = "btime ";
	line = find_line_p("/proc/stat", needle);
	if (line == NULL)
		return (0);
	btime = strtonum(line + strlen(needle), 1, LLONG_MAX, &errstr);
	free(line);
	if (errstr != NULL)
		qwarnx("can't parse btime: %s", errstr);

	return (btime * NS_PER_S);
}

/*
 * Aggregation is a relationship between a parent event and a child event. In a
 * fork+exec cenario, fork is the parent, exec is the child.
 * Aggregation can be confiured as AGG_SINGLE or AGG_MULTI.
 *
 * AGG_SINGLE aggregate a single child: fork+exec+exec would result
 * in two events: (fork+exec); (exec).
 *
 * AGG_MULTI just smashes everything together, a fork+comm+comm+comm would
 * result in one event: (fork+comm), the intermediary comm values are lost.
 */

enum agg_kind {
	AGG_NONE,		/* Can't aggregate, must be zero */
	AGG_SINGLE,		/* Can aggregate only one value */
	AGG_MULTI		/* Can aggregate multiple values */
};
		     /* parent */   /* child */
const u8 agg_matrix[RAW_NUM_TYPES][RAW_NUM_TYPES] = {
	[RAW_WAKE_UP_NEW_TASK][RAW_EXEC]		= AGG_SINGLE,
	[RAW_WAKE_UP_NEW_TASK][RAW_EXEC_CONNECTOR]	= AGG_SINGLE,
	[RAW_WAKE_UP_NEW_TASK][RAW_COMM]		= AGG_MULTI,
	[RAW_WAKE_UP_NEW_TASK][RAW_EXIT_THREAD]		= AGG_SINGLE,

	[RAW_EXEC][RAW_EXEC_CONNECTOR]			= AGG_SINGLE,
	[RAW_EXEC][RAW_COMM]				= AGG_MULTI,
	[RAW_EXEC][RAW_EXIT_THREAD]			= AGG_SINGLE,

	[RAW_COMM][RAW_COMM]				= AGG_MULTI,
	[RAW_COMM][RAW_EXIT_THREAD]			= AGG_SINGLE,
};

/* used if qq->flags & QQ_MIN_AGG */
			 /* parent */   /* child */
const u8 agg_matrix_min[RAW_NUM_TYPES][RAW_NUM_TYPES] = {
	[RAW_WAKE_UP_NEW_TASK][RAW_COMM]		= AGG_MULTI,

	[RAW_EXEC][RAW_EXEC_CONNECTOR]			= AGG_SINGLE,
	[RAW_EXEC][RAW_COMM]				= AGG_MULTI,

	[RAW_COMM][RAW_COMM]				= AGG_MULTI,
};

static int
quark_init(void)
{
	unsigned int	hz;
	u64		boottime;

	if (quark.hz && quark.boottime)
		return (0);

	if ((hz = sysconf(_SC_CLK_TCK)) == (unsigned int)-1) {
		qwarn("sysconf(_SC_CLK_TCK)");
		return (-1);
	}
	if ((boottime = fetch_boottime()) == 0) {
		qwarn("can't fetch btime");
		return (-1);
	}
	quark.hz = hz;
	quark.boottime = boottime;

	return (0);
}

#define P(_f, ...)					\
	do {						\
		if (fprintf(_f, __VA_ARGS__) < 0)	\
			return (-1);			\
	} while(0)
static int
write_raw_node_attr(FILE *f, struct raw_event *raw, char *key)
{
	const char		*color;
	char			 label[4096];

	switch (raw->type) {
	case RAW_COMM:
		color = "yellow";
		(void)snprintf(label, sizeof(label), "COMM %s",
		    raw->comm.comm);
		break;
	case RAW_EXIT_THREAD:
		color = "lightseagreen";
		(void)strlcpy(label, "EXIT", sizeof(label));
		break;
	case RAW_EXEC:
		color = "lightslateblue";
		if (snprintf(label, sizeof(label), "EXEC %s",
		    raw->exec.filename.p) >= (int)sizeof(label))
			qwarnx("exec filename truncated");
		break;
	case RAW_WAKE_UP_NEW_TASK: {
		color = "orange";
		if (snprintf(label, sizeof(label), "NEW_TASK %d",
		    raw->pid) >= (int)sizeof(label))
			qwarnx("snprintf label");
		break;
	}
	case RAW_EXEC_CONNECTOR:
		color = "lightskyblue";
		if (snprintf(label, sizeof(label), "EXEC_CONNECTOR")
		    >= (int)sizeof(label))
			qwarnx("exec_connector truncated");
		break;
	default:
		qwarnx("%d unhandled", raw->type);
		color = "black";
		break;
	}
	P(f, "\"%s\" [label=\"%llu\\n%s\\npid %d\", fillcolor=%s];\n",
	    key, raw->time, label, raw->pid, color);

	return (0);
}

int
quark_dump_raw_event_graph(struct quark_queue *qq, FILE *by_time, FILE *by_pidtime)
{
	struct raw_event	*raw, *left, *right;
	FILE			*f;
	char			 key[256];

	f = by_time;

	P(f, "digraph {\n");
	P(f, "node [style=filled, color=black];\n");
	RB_FOREACH(raw, raw_event_by_time, &qq->raw_event_by_time) {
		snprintf(key, sizeof(key), "%llu", raw->time);
		if (write_raw_node_attr(f, raw, key) < 0)
			return (-1);
	}
	RB_FOREACH(raw, raw_event_by_time, &qq->raw_event_by_time) {
		left = RB_LEFT(raw, entry_by_time);
		right = RB_RIGHT(raw, entry_by_time);

		if (left != NULL)
			P(f, "%llu -> %llu;\n",
			    raw->time, left->time);
		if (right != NULL)
			P(f, "%llu -> %llu;\n",
			    raw->time, right->time);
	}
	P(f, "}\n");

	fflush(f);

	f = by_pidtime;

	P(f, "digraph {\n");
	P(f, "node [style=filled, color=black];\n");
	RB_FOREACH(raw, raw_event_by_pidtime, &qq->raw_event_by_pidtime) {
		snprintf(key, sizeof(key), "%d %llu",
		    raw->pid, raw->time);
		if (write_raw_node_attr(f, raw, key) < 0)
			return (-1);
	}
	RB_FOREACH(raw, raw_event_by_pidtime, &qq->raw_event_by_pidtime) {
		left = RB_LEFT(raw, entry_by_pidtime);
		right = RB_RIGHT(raw, entry_by_pidtime);

		if (left != NULL) {
			P(f, "\"%d %llu\" -> \"%d %llu\";\n",
			    raw->pid, raw->time,
			    left->pid, left->time);
		}
		if (right != NULL)
			P(f, "\"%d %llu\" -> \"%d %llu\";\n",
			    raw->pid, raw->time,
			    right->pid, right->time);
	}
	P(f, "}\n");

	fflush(f);

	return (0);
}

int
quark_dump_process_cache_graph(struct quark_queue *qq, FILE *f)
{
	struct quark_process	*qp;
	const char		*name;
	const char		*color_table[] = {
		"aqua",
		"aquamarine3",
		"azure3",
		"coral",
		"darkgoldenrod1",
		"darkolivegreen2",
		"darkorchid1",
		"firebrick3",
		"forestgreen",
		"lemonchiffon2",
		"lightslateblue",
		"lime",
		"orange2",
		"skyblue3",
		"violet",
		"yellow"
	};

	P(f, "digraph {\n");
	P(f, "ranksep=2.0;\n");
	P(f, "nodesep=0.65;\n");
	P(f, "node [style=filled, shape=box, color=black];\n");
	RB_FOREACH(qp, process_by_pid, &qq->process_by_pid) {
		uint	color_index;

		color_index = (uint)qp->proc_ppid % (uint)nitems(color_table);
		if (color_index >= nitems(color_table)) /* paranoia */
			color_index = 0;

#ifdef notyet
		struct args	*args;
		int		 i;
#endif
		if (qp->flags & QUARK_F_FILENAME)
			name = qp->filename;
		else if (qp->flags & QUARK_F_COMM)
			name = qp->comm;
		else
			name = "<unknown>";
		P(f, "\"%d\" [label=\"%d\\n%s\\n", qp->pid, qp->pid, name);
		if (qp->flags & QUARK_F_COMM)
			P(f, "comm %s\\n", qp->comm);
		if (qp->flags & QUARK_F_CWD)
			P(f, "cwd %s\\n", qp->cwd);
#ifdef notyet
		P(f, "args [");
		args = args_make(qp);
		if (args == NULL)
			P(f, "(%s)", strerror(errno));
		else {
			for (i = 0; i < args->argc; i++) {
				if (i > 0)
					P(f, " ");
				P(f, "%s", args->argv[i]);
			}
			args_free(args);
		}
		P(f, " ]\\n");
#endif
		if (qp->flags & QUARK_F_PROC) {
			P(f, "cap_inh 0x%llx\\n", qp->proc_cap_inheritable);
			P(f, "cap_per 0x%llx\\n", qp->proc_cap_permitted);
			P(f, "cap_eff 0x%llx\\n", qp->proc_cap_effective);
			P(f, "cap_bset 0x%llx\\n", qp->proc_cap_bset);
			P(f, "cap_amb 0x%llx\\n", qp->proc_cap_ambient);
			P(f, "time_boot %llu\\n", qp->proc_time_boot);
			P(f, "uid %d\\n", qp->proc_uid);
			P(f, "gid %d\\n", qp->proc_gid);
			P(f, "suid %d\\n", qp->proc_suid);
			P(f, "sgid %d\\n", qp->proc_sgid);
			P(f, "sid %d\\n", qp->proc_sid);
			P(f, "tty_maj %d\\n", qp->proc_tty_major);
			P(f, "tty_min %d\\n", qp->proc_tty_minor);
			P(f, "el_type %s\\n",
			    entry_leader_type_str(qp->proc_entry_leader_type));
			P(f, "el_leader %d\\n", qp->proc_entry_leader);
		}
		if (qp->flags & QUARK_F_EXIT) {
			P(f, "exit %d\\n", qp->exit_code);
			P(f, "exit_time %llu\\n", qp->exit_time_event);
		}
		P(f, "flags 0x%llx\\n", qp->flags);
		P(f, "\", fillcolor=%s];\n", color_table[color_index]);
	}
	RB_FOREACH(qp, process_by_pid, &qq->process_by_pid) {
		P(f, "%d -> %d;\n", qp->proc_ppid, qp->pid);
	}
	P(f, "}\n");
	fflush(f);

	return (0);
}
#undef P

int
quark_queue_get_epollfd(struct quark_queue *qq)
{
	return (qq->epollfd);
}

void
quark_queue_get_stats(struct quark_queue *qq, struct quark_queue_stats *qs)
{
	qq->queue_ops->update_stats(qq);
	*qs = qq->stats;
}

int
quark_queue_block(struct quark_queue *qq)
{
	struct epoll_event	 ev;

	if (qq->epollfd == -1)
		return (errno = EINVAL, -1);
	if (epoll_wait(qq->epollfd, &ev, 1, 100) == -1)
		return (-1);

	return (0);
}

void
quark_queue_default_attr(struct quark_queue_attr *qa)
{
	bzero(qa, sizeof(*qa));

	qa->flags = QQ_ALL_BACKENDS;
	qa->max_length = 10000;
	qa->cache_grace_time = 4000;	/* four seconds */
	qa->hold_time = 1000;		/* one second */
}

int
quark_queue_open(struct quark_queue *qq, struct quark_queue_attr *qa)
{
	struct quark_process		*qp;
	struct quark_queue_attr		 qa_default;

	if (qa == NULL) {
		quark_queue_default_attr(&qa_default);
		qa = &qa_default;
	}

	if ((qa->flags & QQ_ALL_BACKENDS) == 0 ||
	    qa->max_length <= 0 ||
	    qa->cache_grace_time < 0 ||
	    qa->hold_time < 10)
		return (errno = EINVAL, -1);

	if (quark_init() == -1)
		return (-1);

	bzero(qq, sizeof(*qq));

	RB_INIT(&qq->raw_event_by_time);
	RB_INIT(&qq->raw_event_by_pidtime);
	RB_INIT(&qq->process_by_pid);
	TAILQ_INIT(&qq->event_gc);
	qq->flags = qa->flags;
	qq->max_length = qa->max_length;
	qq->cache_grace_time = MS_TO_NS(qa->cache_grace_time);
	qq->hold_time = qa->hold_time;
	qq->length = 0;
	qq->epollfd = -1;
	if (qq->flags & QQ_MIN_AGG)
		qq->agg_matrix = agg_matrix_min;
	else
		qq->agg_matrix = agg_matrix;

	if (bpf_queue_open(qq) && kprobe_queue_open(qq)) {
		qwarnx("all backends failed");
		goto fail;
	}

	/*
	 * Now that the rings are opened, we can scrape proc. If we would scrape
	 * before opening them, there would be a small window where we could
	 * lose new processes.
	 */
	if (sproc_scrape(qq) == -1) {
		qwarnx("can't scrape /proc");
		goto fail;
	}

	/*
	 * Compute all entry leaders
	 */
	if (entry_leaders_build(qq) == -1) {
		qwarnx("can't compute entry leaders");
		return (-1);
	}

	/*
	 * We want quark_get_events() to start by giving up a snapshot of
	 * everything we scraped, this snapshot will end up being spread into
	 * multiple quark_get_events() calls as there isn't enough storage for
	 * all of them. We need a way to know where we are in the snapshot.
	 */
	if (qq->flags & QQ_NO_SNAPSHOT)
		qq->snap_pid = -1;
	else {
		qp = RB_MIN(process_by_pid, &qq->process_by_pid);
		if (qp != NULL)
			qq->snap_pid = qp->pid;
		else
			qq->snap_pid = -1;
	}

	return (0);

fail:
	quark_queue_close(qq);

	return (-1);
}

/*
 * Must be careful enough that can be called if quark_queue_open() fails
 */
void
quark_queue_close(struct quark_queue *qq)
{
	struct raw_event		*raw;
	struct quark_process		*qp;

	/* Clean up all allocated raw events */
	while ((raw = RB_ROOT(&qq->raw_event_by_time)) != NULL) {
		raw_event_remove(qq, raw);
		raw_event_free(raw);
	}
	if (!RB_EMPTY(&qq->raw_event_by_pidtime))
		qwarnx("raw_event trees not empty");
	/* Clean up all cached quark_processs */
	while ((qp = RB_ROOT(&qq->process_by_pid)) != NULL)
		process_cache_delete(qq, qp);
	/* Clean up backend */
	if (qq->queue_ops != NULL)
		qq->queue_ops->close(qq);
}

static int
can_aggregate(struct quark_queue *qq, struct raw_event *p, struct raw_event *c)
{
	int			 kind;
	struct raw_event	*agg;

	/* Different pids can't aggregate */
	if (p->pid != c->pid)
		return (0);

	if (p->type >= RAW_NUM_TYPES || c->type >= RAW_NUM_TYPES ||
	    p->type <= RAW_INVALID || c->type <= RAW_INVALID) {
		qwarnx("type out of bounds p=%d c=%d", p->type, c->type);
		return (0);
	}

	kind = qq->agg_matrix[p->type][c->type];

	switch (kind) {
	case AGG_NONE:
		return (0);
	case AGG_MULTI:
		return (1);
	case AGG_SINGLE:
		TAILQ_FOREACH(agg, &p->agg_queue, agg_entry) {
			if (agg->type == c->type)
				return (0);
		}
		return (1);
	default:
		qwarnx("unhandle agg kind %d", kind);
		return (0);
	}
}

static void
quark_queue_aggregate(struct quark_queue *qq, struct raw_event *min)
{
	struct raw_event	*next, *aux;
	int			 agg;

	agg = 0;

	next = RB_NEXT(raw_event_by_pidtime, &qq->raw_event_by_pidtime,
	    min);
	while (next != NULL) {
		if (!can_aggregate(qq, min, next))
			break;
		aux = next;
		next = RB_NEXT(raw_event_by_pidtime,
		    &qq->raw_event_by_pidtime, next);
		raw_event_remove(qq, aux);
		TAILQ_INSERT_TAIL(&min->agg_queue, aux, agg_entry);
		agg++;
	}

	if (agg)
		qq->stats.aggregations++;
	else
		qq->stats.non_aggregations++;
}

int
quark_queue_populate(struct quark_queue *qq)
{
	return (qq->queue_ops->populate(qq));
}

static struct raw_event *
quark_queue_pop_raw(struct quark_queue *qq)
{
	struct raw_event	*min;
	u64			 now;

	/*
	 * We populate before draining so we can have a fuller tree for
	 * aggregation.
	 */
	(void)quark_queue_populate(qq);

	now = now64();
	min = RB_MIN(raw_event_by_time, &qq->raw_event_by_time);
	if (min == NULL || !raw_event_expired(qq, min, now)) {
		/* qq->idle++; */
		return (NULL);
	}

	quark_queue_aggregate(qq, min);
	/* qq->min = RB_NEXT(raw_event_by_time, &qq->raw_event_by_time, min); */
	raw_event_remove(qq, min);

	return (min);
}

int
quark_queue_get_events(struct quark_queue *qq, struct quark_event *qevs,
    int nqevs)
{
	struct raw_event	*raw;
	int			 got;

	got = 0;
	while (got != nqevs) {
		/* Are we in the middle of a snapshot? */
		if (unlikely(qq->snap_pid != -1)) {
			struct quark_process	*qp;

			qp = process_cache_get(qq, qq->snap_pid, 0);
			if (qp == NULL) {
				qwarnx("event vanished during snapshot, "
				    "this is a bug");
				qq->snap_pid = -1;
				/* errno set by cache_lookup */
				return (-1);
			}
			/* Copy out to user */
			qevs->events = QUARK_EV_SNAPSHOT;
			qevs->process = qp;
			qp = RB_NEXT(process_by_pid, &qq->process_by_pid, qp);
			/* Are we done with the snapshot? If not, record next */
			if (qp == NULL)
				qq->snap_pid = -1;
			else
				qq->snap_pid = qp->pid;
		} else {
			raw = quark_queue_pop_raw(qq);
			if (raw == NULL)
				break;
			if (raw_event_process(qq, raw, qevs) == -1) {
				raw_event_free(raw);
				qwarnx("raw_event_process");
				continue;
			}
			raw_event_free(raw);
		}
		got++;
		qevs++;
	}

	/* GC all processes that exited after some grace time */
	process_cache_gc(qq);

	return (got);
}
mulumulu
