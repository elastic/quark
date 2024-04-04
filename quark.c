#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "quark.h"

#define PERF_MMAP_PAGES		16		/* Must be power of 2 */
#define QUARK_QUEUE_MAXLENGTH	10000		/* XXX hardcoded for now XXX */
#define AGE(_ts, _now) 		((_ts) > (_now) ? 0 : (_now) - (_ts))
#define MAX_SAMPLE_IDS		4096		/* id_to_sample_kind map */
#define EVENT_CACHE_GRACETIME	MS_TO_NS(4000) /* 4 seconds is probably too much */

static int	open_tracing(int, const char *, ...) __attribute__((format(printf, 2, 3)));
static int	raw_event_by_time_cmp(struct raw_event *, struct raw_event *);
static int	raw_event_by_pidtime_cmp(struct raw_event *, struct raw_event *);
static int	event_by_pid_cmp(struct quark_event *, struct quark_event *);

/* For debugging */
int	quark_verbose;

/* matches each sample event to a kind like EXEC_SAMPLE, FOO_SAMPLE */
u8	id_to_sample_kind[MAX_SAMPLE_IDS];

RB_PROTOTYPE(event_by_pid, quark_event,
    entry_by_pid, event_by_pid_cmp);
RB_GENERATE(event_by_pid, quark_event,
    entry_by_pid, event_by_pid_cmp);

RB_PROTOTYPE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);
RB_GENERATE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);

RB_PROTOTYPE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);
RB_GENERATE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);

struct {
	unsigned int	hz;
	u64		boottime;

	/*
	 * This is the offset from the common area of a probe to the body. It is almost
	 * always 8, but some older redhat kernels are different.
	 */
	ssize_t		probe_data_body_offset;
} hostinfo;

static struct raw_event *
raw_event_alloc(void)
{
	struct raw_event *raw;

	raw = calloc(1, sizeof(*raw));
	if (raw != NULL)
		TAILQ_INIT(&raw->agg_queue);

	return (raw);
}

static void
raw_event_free(struct raw_event *raw)
{
	struct raw_event *aux;

	switch (raw->type) {
	case RAW_EXEC:
		qstr_free(&raw->exec.filename);
		break;
	case RAW_WAKE_UP_NEW_TASK:
	case RAW_EXIT_THREAD:
		qstr_free(&raw->task.cwd);
		break;
	case RAW_EXEC_CONNECTOR:
		qstr_free(&raw->exec_connector.args);
		break;
	default:
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

/* XXX this should be by tid, but we're not there yet XXX */
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

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == -1)
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
raw_event_target_age(int maxn, int n)
{
	int	v;

	if (n < (maxn / 10))
		v = 1000;
	else if (n < ((maxn / 10) * 9))
		v = 1000 - (n / (maxn / 1000)) + 1;
	else
		v = 0;

	return ((u64)MS_TO_NS(v));
}

static inline int
raw_event_expired(struct quark_queue *qq, struct raw_event *raw, u64 now)
{
	u64	target;

	target = raw_event_target_age(qq->max_length, qq->length);
	return (raw_event_age(raw, now) >= target);
}

/*
 * Insert without a colision, cheat on the timestamp in case we do. NOTE: since
 * we bump "time" here, we shouldn't copy "time" before it sits in the tree.
 */
static void
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
		warnx("raw_event_by_time collision");
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

#if 0
static void
raw_event_dump(struct raw_event *raw, int is_agg)
{
	struct raw_event	*agg;
	char			*header;

	header = is_agg ? "\t++" : "->";

	switch (raw->type) {
	case RAW_WAKE_UP_NEW_TASK: /* FALLTHROUGH */
	case RAW_EXIT_THREAD: {
		struct raw_task		*w = &raw->task;
		const char		*head;

		head = raw->type == RAW_WAKE_UP_NEW_TASK ?
		    "wake_up_new_task" : "exit_thread";
		printf("%s%s (%d)\n\t", header, head, raw->pid);
		printf("pid=%d tid=%d uid=%d gid=%d suid=%d sgid=%d euid=%d egid=%d\n",
		    raw->pid, raw->tid, w->uid, w->gid, w->suid, w->sgid, w->euid,
		    w->egid);
		printf("\tstart_boottime=%llu", w->start_boottime);

		raw->type == RAW_WAKE_UP_NEW_TASK ? "start" : "end");
		printf(" norm_%s=%llu", raw->time,
		    raw->type == RAW_WAKE_UP_NEW_TASK ? "start" : "end");
		printf("\n");
		printf("\tcap_inheritable=0x%llx cap_permitted=0x%llx cap_effective=0x%llx\n"
		    "\tcap_bset=0x%llx cap_ambient=0x%llx\n",
		    w->cap_inheritable, w->cap_permitted, w->cap_effective,
		    w->cap_bset, w->cap_ambient);
		if (raw->type == RAW_WAKE_UP_NEW_TASK) {
			printf("\tworking_directory=%s\n", w->cwd);
			printf("\tppid=%d\n", w->ppid);
		} else if (raw->type == RAW_EXIT_THREAD)
			printf("\texit_code=%d exit_time_event=%llu\n",
			    w->exit_code, w->exit_time_event);
		TAILQ_FOREACH(agg, &raw->agg_queue, agg_entry) {
			raw_event_dump(agg, 1);
		}
		break;
	}
	case RAW_EXEC:
		printf("%sexec (%d)\n\tfilename=%s\n",
		    header, raw->pid, raw->exec.filename.p);
		break;
	case RAW_COMM:
		printf("%scomm (%d)\n\tcomm=%s\n", header, raw->pid, raw->comm.comm);
		break;
	case RAW_EXEC_CONNECTOR: {
		int	 argc;
		char	*p;

		printf("%sexec_connector (%d)\n\targs=", header, raw->pid);
		p = raw->exec_connector.args.p;
		for (argc = 0; argc < raw->exec_connector.argc; argc++) {
			printf("%s ", p);
			p += strlen(p) + 1;
		}
		printf("\n");
		break;
	}
	default:
		warnx("%s unhandled(type %d, pid %d)\n",
		    __func__, raw->type, raw->pid);
		break;
	}

	fflush(stdout);
}
#endif

/* buf_len includes the terminating NUL */
static int
args_to_spaces(char *buf, size_t buf_len)
{
	char	*p, *last;

	if (buf_len == 0)
		return (-1);

	/* last points to the last NUL */
	last = &buf[buf_len - 1];
	if (*last != 0)
		return (-1);
	for (p = buf + strlen(buf); p != last; p += strlen(p))
		*p = ' ';

	return (0);
}

static void
event_copy_fields(struct quark_event *dst, struct quark_event *src)
{
#define MCPY(_f, _l)	memcpy(dst->_f, src->_f, src->_l)
#define STCPY(_f)	strlcpy(dst->_f, src->_f, sizeof(dst->_f))
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
event_copy_out(struct quark_event *dst, struct quark_event *src, u64 events)
{
	bzero(&dst->quark_event_zero_start,
	    (char *)&dst->quark_event_zero_end - (char *)&dst->quark_event_zero_start);
	dst->events = events;
	dst->pid = src->pid;
	event_copy_fields(dst, src);
}

static struct quark_event *
event_cache_get(struct quark_queue *qq, int pid, int alloc)
{
	struct quark_event	 key;
	struct quark_event	*qev;

	key.pid = pid;
	qev = RB_FIND(event_by_pid, &qq->event_by_pid, &key);
	if (qev != NULL)
		return (qev);

	if (!alloc) {
		errno = ESRCH;
		return (NULL);
	}

	qev = calloc(1, sizeof(*qev));
	if (qev == NULL)
		return (NULL);
	qev->pid = pid;
	if (RB_INSERT(event_by_pid, &qq->event_by_pid, qev) != NULL) {
		warnx("collision, this is a bug");
		free(qev);
		return (NULL);
	}

	return (qev);
}

static void
event_cache_inherit(struct quark_queue *qq, struct quark_event *qev, int ppid)
{
	struct quark_event	*parent;

	if ((parent = event_cache_get(qq, ppid, 0)) == NULL)
		return;

	if (parent->flags & QUARK_F_COMM) {
		qev->flags |= QUARK_F_COMM;
		strlcpy(qev->comm, parent->comm, sizeof(qev->comm));
	}
	if (parent->flags & QUARK_F_FILENAME) {
		qev->flags |= QUARK_F_FILENAME;
		strlcpy(qev->filename, parent->filename, sizeof(qev->filename));
	}
	/* Do we really want CMDLINE? */
	if (parent->flags & QUARK_F_CMDLINE) {
		qev->flags |= QUARK_F_CMDLINE;
		qev->cmdline_len = parent->cmdline_len;
		memcpy(qev->cmdline, parent->cmdline, parent->cmdline_len);
	}
}

static void
event_cache_delete(struct quark_queue *qq, struct quark_event *qev)
{
	RB_REMOVE(event_by_pid, &qq->event_by_pid, qev);
	if (qev->gc_time)
		TAILQ_REMOVE(&qq->event_gc, qev, entry_gc);
	free(qev);
}

static int
event_cache_gc(struct quark_queue *qq)
{
	struct quark_event	*qev;
	u64			 now;
	int			 n;

	now = now64();
	n = 0;
	while ((qev = TAILQ_FIRST(&qq->event_gc)) != NULL) {
		if (AGE(qev->gc_time, now) < EVENT_CACHE_GRACETIME)
			break;
		event_cache_delete(qq, qev);
		n++;
	}

	return (n);
}

static int
event_by_pid_cmp(struct quark_event *a, struct quark_event *b)
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

/* User facing version of event_cache_lookup() */
int
quark_event_lookup(struct quark_queue *qq, struct quark_event *dst, int pid)
{
	struct quark_event	*qev;

	qev = event_cache_get(qq, pid, 0);
	if (qev == NULL)
		return (-1);

	event_copy_out(dst, qev, 0);

	return (0);
}

#define P(...)						\
	do {						\
		if (fprintf(f, __VA_ARGS__) < 0)	\
			return (-1);			\
	} while(0)
int
quark_event_dump(struct quark_event *qev, FILE *f)
{
	const char	*flagname;
	char		 events[1024];

	/* TODO: add tid */
	events_type_str(qev->events, events, sizeof(events));
	P("->%d (%s)\n", qev->pid, events);
	if (qev->flags & QUARK_F_COMM) {
		flagname = event_flag_str(QUARK_F_COMM);
		P("  %.4s\tcomm=%s\n", flagname, qev->comm);
	}
	if (qev->flags & QUARK_F_CMDLINE) {
		flagname = event_flag_str(QUARK_F_CMDLINE);

		if (0) {
			args_to_spaces(qev->cmdline, qev->cmdline_len);
			P("  %.4s\tcmdline=%s\n", flagname, qev->cmdline);
		} else {
			int		 i;
			struct args	*args;

			P("  %.4s\tcmdline=", flagname);
			P("[ ");
			args = args_make(qev);
			if (args == NULL)
				P("(%s)", strerror(errno));
			else {
				for (i = 0; i < args->argc; i++) {
					if (i > 0)
						P(", ");
					P("%s", args->argv[i]);
				}
			}
			P(" ]\n");
			args_free(args);
		}
	}
	if (qev->flags & QUARK_F_PROC) {
		flagname = event_flag_str(QUARK_F_PROC);
		P("  %.4s\tppid=%d\n", flagname, qev->proc_ppid);
		P("  %.4s\tuid=%d gid=%d suid=%d sgid=%d euid=%d egid=%d\n",
		    flagname, qev->proc_uid, qev->proc_gid, qev->proc_suid,
		    qev->proc_sgid, qev->proc_euid, qev->proc_egid);
		P("  %.4s\tcap_inheritable=0x%llx cap_permitted=0x%llx "
		    "cap_effective=0x%llx\n",
		    flagname, qev->proc_cap_inheritable,
		    qev->proc_cap_permitted, qev->proc_cap_effective);
		P("  %.4s\tcap_bset=0x%llx cap_ambient=0x%llx\n",
		    flagname, qev->proc_cap_bset, qev->proc_cap_ambient);
		P("  %.4s\ttime_boot=%llu\n", flagname, qev->proc_time_boot);
	}
	if (qev->flags & QUARK_F_CWD) {
		flagname = event_flag_str(QUARK_F_CWD);
		P("  %.4s\tcwd=%s\n", flagname, qev->cwd);
	}
	if (qev->flags & QUARK_F_FILENAME) {
		flagname = event_flag_str(QUARK_F_FILENAME);
		P("  %.4s\tfilename=%s\n", flagname, qev->filename);
	}
	if (qev->flags & QUARK_F_EXIT) {
		flagname = event_flag_str(QUARK_F_EXIT);
		P("  %.4s\texit_code=%d exit_time=%llu\n", flagname,
		    qev->exit_code, qev->exit_time_event);
	}

	fflush(f);

	return (0);
}
#undef P

static int
raw_event_to_quark_event(struct quark_queue *qq, struct raw_event *raw, struct quark_event *dst)
{
	struct quark_event		*qev;
	struct raw_event                *agg;
	struct raw_task                 *task, *exit;
	struct raw_comm                 *comm;
	struct raw_exec                 *exec;
	struct raw_exec_connector       *exec_connector;
	int				 do_cache;
	u64				 events;

	task = NULL;
	exit = NULL;
	comm = NULL;
	exec = NULL;
	exec_connector = NULL;
	do_cache = (qq->flags & QQ_NO_CACHE) == 0;

	if (do_cache) {
		/* XXX pass if this is a fork down, so we can evict the old one XXX */
		qev = event_cache_get(qq, raw->pid, 1);
		if (qev == NULL)
			return (-1);
	} else {
		qev = dst;
		qev->pid = raw->pid;
		qev->flags = 0;
	}

	events = 0;

	switch (raw->type) {
	case RAW_WAKE_UP_NEW_TASK:
		events |= QUARK_EV_FORK;
		task = &raw->task;
		break;
	case RAW_EXEC:
		events |= QUARK_EV_EXEC;
		exec = &raw->exec;
		break;
	case RAW_EXIT_THREAD:
		events |= QUARK_EV_EXIT;
		exit = &raw->task;
		break;
	case RAW_COMM:
		events |= QUARK_EV_SETPROCTITLE;
		comm = &raw->comm;
		break;
	case RAW_EXEC_CONNECTOR:
		events |= QUARK_EV_EXEC;
		exec_connector = &raw->exec_connector;
		break;
	default:
		return (errno = EINVAL, -1);
		break;		/* NOTREACHED */
	};

	TAILQ_FOREACH(agg, &raw->agg_queue, agg_entry) {
		switch (agg->type) {
		case RAW_WAKE_UP_NEW_TASK:
			task = &agg->task;
			events |= QUARK_EV_FORK;
			break;
		case RAW_EXEC:
			events |= QUARK_EV_EXEC;
			exec = &agg->exec;
			break;
		case RAW_EXIT_THREAD:
			events |= QUARK_EV_EXIT;
			exit = &agg->task;
			break;
		case RAW_COMM:
			events |= QUARK_EV_SETPROCTITLE;
			comm = &agg->comm;
			break;
		case RAW_EXEC_CONNECTOR:
			events |= QUARK_EV_EXEC;
			exec_connector = &agg->exec_connector;
			break;
		default:
			break;
		}
	}

	/* QUARK_F_PROC */
	if (task != NULL) {
		qev->flags |= QUARK_F_PROC;

		if (events & QUARK_EV_FORK)
			event_cache_inherit(qq, qev, task->ppid);

		qev->proc_cap_inheritable = task->cap_inheritable;
		qev->proc_cap_permitted = task->cap_permitted;
		qev->proc_cap_effective = task->cap_effective;
		qev->proc_cap_bset = task->cap_bset;
		qev->proc_cap_ambient = task->cap_ambient;
		qev->proc_time_boot = hostinfo.boottime + task->start_boottime;
		qev->proc_ppid = task->ppid;
		qev->proc_uid = task->uid;
		qev->proc_gid = task->gid;
		qev->proc_suid = task->suid;
		qev->proc_sgid = task->sgid;
		qev->proc_euid = task->euid;
		qev->proc_egid = task->egid;

		qev->flags |= QUARK_F_CWD;
		strlcpy(qev->cwd, task->cwd.p, sizeof(qev->cwd));
	}
	if (exit != NULL) {
		qev->flags |= QUARK_F_EXIT;

		qev->exit_code = exit->exit_code;
		qev->exit_time_event = exit->exit_time_event;
		/* XXX considering updating task values since we have it here XXX */
	}
	if (exec != NULL) {
		qev->flags |= QUARK_F_FILENAME;

		strlcpy(qev->filename, exec->filename.p, sizeof(qev->filename));
	}
	if (exec_connector != NULL) {
		size_t		 copy_len;

		qev->flags |= QUARK_F_CMDLINE;

		qev->cmdline[0] = 0;
		copy_len = min(sizeof(qev->cmdline), exec_connector->args_len);
		if (copy_len > 0) {
			memcpy(qev->cmdline, exec_connector->args.p, copy_len);
			qev->cmdline[copy_len - 1] = 0;
		}
		qev->cmdline_len = copy_len;

		qev->flags |= QUARK_F_COMM;
		strlcpy(qev->comm, exec_connector->comm, sizeof(qev->comm));
	}
	if (comm != NULL) {
		qev->flags |= QUARK_F_COMM;

		strlcpy(qev->comm, comm->comm, sizeof(qev->comm));
	}

	if (qev->flags == 0)
		warnx("%s: no flags", __func__);

	if (do_cache) {
		event_copy_out(dst, qev, events);

		/*
		 * On the very unlikely case that pids get re-used, we might
		 * see an old qev for a new process, which could prompt us in
		 * trying to remove it twice.
		 */
		if (exit != NULL && qev->gc_time == 0) {
			qev->gc_time = now64();
			TAILQ_INSERT_TAIL(&qq->event_gc, qev, entry_gc);
		}
	} else
		qev->events = events;

	return (0);
}

static char *
str_of_dataloc(struct perf_record_sample *sample,
    struct perf_sample_data_loc *data_loc)
{
	return (sample->data + data_loc->offset);
}

#if 0
/*
 * Copies out the string pointed to by data size, if retval is >= than dst_size,
 * it means we truncated. May return -1 on bad values.
 */
static ssize_t
strlcpy_data_loc(void *dst, ssize_t dst_size,
    struct perf_record_sample *sample, struct perf_sample_data_loc *data_loc)
{
	ssize_t				 n;
	char				*p = dst, *data;

	p = dst;
	n = min(dst_size, data_loc->size);
	if (n <= 0)
		return (-1);
	data = sample->data;
	memcpy(p, data + data_loc->offset, n);
	/* never trust the kernel */
	p[n - 1] = 0;

	return (n - 1);
}
#endif
static inline int
sample_kind_of_id(int id)
{
	if (unlikely(id <= 0 || id >= MAX_SAMPLE_IDS)) {
		warnx("%s: invalid id %d", __func__, id);
		return (errno = ERANGE, -1);
	}

	return (id_to_sample_kind[id]);
}

static inline void *
sample_data_body(struct perf_record_sample *sample)
{
	return (sample->data + hostinfo.probe_data_body_offset);
}

static inline int
sample_data_id(struct perf_record_sample *sample)
{
	struct perf_sample_data_hdr *h = (struct perf_sample_data_hdr *)sample->data;
	return (h->common_type);
}
#if 0
static inline int
sample_kind(struct perf_record_sample *sample)
{
	return (sample_kind_of_id(sample_data_id(sample)));
}
#endif

static int
build_path(struct path_ctx *ctx, struct qstr *dst)
{
	int	 i, done;
	char	*p, *pwd, *ppwd, path[MAXPATHLEN];
	u64	 pwd_k;

	p = &path[sizeof(path) - 1];
	*p = 0;
	done = 0;
	for (i = 0; i < (int)nitems(ctx->pwd) && !done; i++) {
		pwd_k = ctx->pwd[i].pwd_k;
		pwd = ctx->pwd[i].pwd;
		if (pwd_k == ctx->root_k)
			break;
		if (pwd_k == ctx->mnt_root_k) {
			pwd = ctx->mnt_mountpoint;
			done = 1;
		}
		/* XXX this strlen sucks as we had the length on the wire */
		ppwd = pwd + strlen(pwd);
		/* +1 is the / */
		/* XXX this is way too dangerous XXX */
		if (((ppwd - pwd) + 1) > (p - path))
			return (errno = ENAMETOOLONG, -1);
		while (ppwd != pwd)
			*--p = *--ppwd;
		*--p = '/';
	}
	if (*p == 0)
		*--p = '/';

	/* XXX double copy XXX */
	return (qstr_strcpy(dst, p));
}

static struct raw_event *
perf_sample_to_raw(struct quark_queue *qq, struct perf_record_sample *sample)
{
	int			 id, kind;
	ssize_t			 n;
	struct raw_event	*raw = NULL;

	id = sample_data_id(sample);
	kind = sample_kind_of_id(id);

	switch (kind) {
	case EXEC_SAMPLE: {
		struct exec_sample *exec = sample_data_body(sample);
		if ((raw = raw_event_alloc()) == NULL)
			return (NULL);
		raw->type = RAW_EXEC;
		qstr_init(&raw->exec.filename);
		n = qstr_copy_data_loc(&raw->exec.filename, sample, &exec->filename);
		if (n == -1)
			warnx("can't copy exec filename");
		break;
	}
	case WAKE_UP_NEW_TASK_SAMPLE: /* FALLTHROUGH */
	case EXIT_THREAD_SAMPLE: {
		struct task_sample	*w = sample_data_body(sample);
		struct path_ctx		 pctx;
		int			 i;
		/*
		 * ev->sample.sample_id.pid is the parent, if the new task has
		 * the same pid as it, then this is a thread event
		 */
		if ((qq->flags & QQ_THREAD_EVENTS) == 0
		    && w->pid != w->tid)
			return (NULL);
		if ((raw = raw_event_alloc()) == NULL)
			return (NULL);
		if (kind == WAKE_UP_NEW_TASK_SAMPLE) {
			raw->type = RAW_WAKE_UP_NEW_TASK;
			/*
			 * Cheat, make this look like a child event.
			 */
			raw->pid = w->pid;
			raw->tid = w->tid;
			raw->task.ppid = sample->sample_id.pid;
			pctx.root = str_of_dataloc(sample, &w->root_s);
			pctx.root_k = w->root_k;
			pctx.mnt_root = str_of_dataloc(sample, &w->mnt_root_s);
			pctx.mnt_root_k = w->mnt_root_k;
			pctx.mnt_mountpoint = str_of_dataloc(sample,
			    &w->mnt_mountpoint_s);
			pctx.mnt_mountpoint_k = w->mnt_mountpoint_k;
			for (i = 0; i < (int)nitems(pctx.pwd); i++) {
				pctx.pwd[i].pwd = str_of_dataloc(sample,
				    &w->pwd_s[i]);
				pctx.pwd[i].pwd_k = w->pwd_k[i];
			}
			qstr_init(&raw->task.cwd);
			if (build_path(&pctx, &raw->task.cwd) == -1)
				warn("can't build path");
			raw->task.exit_code = -1;
			raw->task.exit_time_event = 0;
		} else {
			raw->type = RAW_EXIT_THREAD;
			/*
			 * We derive ppid from the incoming sample header as
			 * it's originally an event of the parent, since exit is
			 * originally an event of the child, we don't have
			 * access to ppid.
			 */
			raw->task.ppid = -1;
			raw->task.exit_code = w->exit_code;
			raw->task.exit_time_event = sample->sample_id.time;
		}
		raw->task.cap_inheritable = w->cap_inheritable;
		raw->task.cap_permitted = w->cap_permitted;
		raw->task.cap_effective = w->cap_effective;
		raw->task.cap_bset = w->cap_bset;
		raw->task.cap_ambient = w->cap_ambient;
		raw->task.start_boottime = w->start_boottime;
		raw->task.uid = w->uid;
		raw->task.gid = w->gid;
		raw->task.suid = w->suid;
		raw->task.sgid = w->sgid;
		raw->task.euid = w->euid;
		raw->task.egid = w->egid;

		break;
	}
	case EXEC_CONNECTOR_SAMPLE: {
		char				*start, *p, *end;
		int				 i;
		struct exec_connector_sample	*exec_sample = sample_data_body(sample);
		struct raw_exec_connector	*exec;

		if ((raw = raw_event_alloc()) == NULL)
			return (NULL);
		raw->type = RAW_EXEC_CONNECTOR;
		exec = &raw->exec_connector;
		qstr_init(&exec->args);

		start = p = (char *)&exec_sample->stack[0];
		end = start + sizeof(exec_sample->stack);

		for (i = 0; i < (int)exec_sample->argc && p < end; i++)
			p += strnlen(p, end - p) + 1;
		if (p >= end)
			p = end;
		exec->args_len = p - start;
		if (exec->args_len == 0)
			exec->args.p[0] = 0;
		else {
			if (qstr_memcpy(&exec->args, start, exec->args_len) == -1)
				warnx("can't copy args");
			exec->args.p[exec->args_len - 1] = 0;
		}
		strlcpy(exec->comm, str_of_dataloc(sample, &exec_sample->comm),
		    sizeof(exec->comm));
		break;
	}
	default:
		warnx("%s: unknown or invalid sample id=%d", __func__, id);
		return (NULL);
	}

	return (raw);
}

static struct raw_event *
perf_event_to_raw(struct quark_queue *qq, struct perf_event *ev)
{
	struct raw_event		*raw = NULL;
	struct perf_sample_id		*sid = NULL;
	ssize_t				 n;

	switch (ev->header.type) {
	case PERF_RECORD_SAMPLE:
		raw = perf_sample_to_raw(qq, &ev->sample);
		if (raw != NULL)
			sid = &ev->sample.sample_id;
		break;
	case PERF_RECORD_COMM:
		/*
		 * Supress comm events due to exec as we can fetch comm
		 * directly from the task struct
		 */
		if (ev->header.misc & PERF_RECORD_MISC_COMM_EXEC)
			return (NULL);
		if ((qq->flags & QQ_THREAD_EVENTS) == 0 &&
		    ev->comm.pid != ev->comm.tid)
			return (NULL);
		if ((raw = raw_event_alloc()) == NULL)
			return (NULL);
		raw->type = RAW_COMM;
		n = strlcpy(raw->comm.comm, ev->comm.comm,
		    sizeof(raw->comm.comm));
		/*
		 * Yes, comm is variable length, maximum 16. The kernel
		 * guarantees alignment on an 8byte boundary for the sample_id,
		 * that means we have to calculate the next boundary.
		 */
		sid = (struct perf_sample_id *)
		    ALIGN_UP(ev->comm.comm + n + 1, 8);
		break;
	case PERF_RECORD_FORK:
	case PERF_RECORD_EXIT:
		/*
		 * As long as we are still using PERF_RECORD_COMM events, the
		 * kernel implies we want FORK and EXIT as well, see
		 * core.c:perf_event_task_match(), this is likely unintended
		 * behaviour.
		 */
		break;
	case PERF_RECORD_LOST:
		qq->stats.lost += ev->lost.lost;
		break;
	default:
		warnx("%s unhandled type %d\n", __func__, ev->header.type);
		return (NULL);
		break;
	}

	if (sid != NULL) {
		/* FORK/WAKE_UP_NEW_TASK overloads pid and tid */
		if (raw->pid == 0)
			raw->pid = sid->pid;
		if (raw->tid == 0)
			raw->tid = sid->tid;
		raw->opid = sid->pid;
		raw->tid = sid->tid;
		raw->time = sid->time;
		raw->cpu = sid->cpu;
	}

	return (raw);
}

static int
perf_mmap_init(struct perf_mmap *mm, int fd)
{
	mm->mapped_size = (1 + PERF_MMAP_PAGES) * getpagesize();
	mm->metadata = mmap(NULL, mm->mapped_size, PROT_READ|PROT_WRITE,
	    MAP_SHARED, fd, 0);
	if (mm->metadata == NULL)
		return (-1);
	mm->data_size = PERF_MMAP_PAGES * getpagesize();
	mm->data_mask = mm->data_size - 1;
	mm->data_start = (uint8_t *)mm->metadata + getpagesize();
	mm->data_tmp_tail = mm->metadata->data_tail;

	return (0);
}

static inline uint64_t
perf_mmap_load_head(struct perf_event_mmap_page *metadata)
{
	return (__atomic_load_n(&metadata->data_head, __ATOMIC_ACQUIRE));
}

static inline void
perf_mmap_update_tail(struct perf_event_mmap_page *metadata, uint64_t tail)
{
	return (__atomic_store_n(&metadata->data_tail, tail, __ATOMIC_RELEASE));
}

static struct perf_event *
perf_mmap_read(struct perf_mmap *mm)
{
	struct perf_event_header	*evh;
	uint64_t			 data_head;
	int				 diff;
	ssize_t				 leftcont;	/* contiguous size left */

	data_head = perf_mmap_load_head(mm->metadata);
	diff = data_head - mm->data_tmp_tail;
	evh = (struct perf_event_header *)
	    (mm->data_start + (mm->data_tmp_tail & mm->data_mask));

	/* Do we have at least one complete event */
	if (diff < (int)sizeof(*evh) || diff < evh->size)
		return (NULL);
	/* Guard that we will always be able to fit a wrapped event */
	if (unlikely(evh->size > sizeof(mm->wrapped_event_buf)))
		errx(1, "getting an event larger than wrapped buf");
	/* How much contiguous space there is left */
	leftcont = mm->data_size - (mm->data_tmp_tail & mm->data_mask);
	/* Everything fits without wrapping */
	if (likely(evh->size <= leftcont)) {
		mm->data_tmp_tail += evh->size;
		return ((struct perf_event *)evh);
	}
	/*
	 * Slow path, we have to copy the event out in a linear buffer. Start
	 * from the remaining end
	 */
	memcpy(mm->wrapped_event_buf, evh, leftcont);
	/* Copy the wrapped portion from the beginning */
	memcpy(mm->wrapped_event_buf + leftcont, mm->data_start, evh->size - leftcont);
	/* Record where our future tail will be on consume */
	mm->data_tmp_tail += evh->size;

	return ((struct perf_event *)mm->wrapped_event_buf);
}

static inline void
perf_mmap_consume(struct perf_mmap *mmap)
{
	perf_mmap_update_tail(mmap->metadata, mmap->data_tmp_tail);
}

static int
perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
    int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static int
open_tracing(int flags, const char *fmt, ...)
{
	va_list  ap;
	int	 dfd, fd, i, r, saved_errno;
	char	 tail[MAXPATHLEN];
	char	*paths[] = {
		"/sys/kernel/tracing",
		"/sys/kernel/debug/tracing",
	};

	va_start(ap, fmt);
	r = vsnprintf(tail, sizeof(tail), fmt, ap);
	va_end(ap);
	if (r == -1 || r >= (int)sizeof(tail))
		return (-1);
	if (tail[0] == '/')
		return (errno = EINVAL, -1);

	saved_errno = 0;
	for (i = 0; i < (int)nitems(paths); i++) {
		if ((dfd = open(paths[i], O_PATH)) == -1) {
			if (!saved_errno && errno != ENOENT)
				saved_errno = errno;
			warn("open: %s", paths[i]);
			continue;
		}
		fd = openat(dfd, tail, flags);
		close(dfd);
		if (fd == -1) {
			if (!saved_errno && errno != ENOENT)
				saved_errno = errno;
			warn("open: %s", tail);
			continue;
		}

		return (fd);
	}

	if (saved_errno)
		errno = saved_errno;

	return (-1);
}

static int
fetch_tracing_id(const char *tail)
{
	int		 id, fd;
	char		 idbuf[16];
	const char	*errstr;
	ssize_t		 n;

	fd = open_tracing(O_RDONLY, "%s", tail);
	if (fd == -1)
		return (-1);

	n = qread(fd, idbuf, sizeof(idbuf));
	close(fd);
	if (n <= 0)
		return (-1);
	idbuf[n - 1] = 0;
	id = strtonum(idbuf, 1, MAX_SAMPLE_IDS - 1, &errstr);
	if (errstr != NULL) {
		warnx("strtonum: %s", errstr);
		return (errno = ERANGE, -1);
	}

	return (id);
}

static ssize_t
parse_probe_data_body_offset(void)
{
	int		 fd;
	FILE		*f;
	char		*line, *s, *e;
	const char	*errstr;
	ssize_t		 n, data_offset;
	size_t		 line_len;
	int		 past_common;

	fd = open_tracing(O_RDONLY, "events/sched/sched_process_exec/format");
	if (fd == -1)
		return (-1);
	f = fdopen(fd, "r");
	if (f == NULL) {
		close(fd);
		return (-1);
	}

	past_common = 0;
	line = NULL;
	line_len = 0;
	data_offset = -1;
	while ((n = getline(&line, &line_len, f)) != -1) {
		if (!past_common) {
			past_common = !strcmp(line, "\n");
			continue;
		}
		s = strstr(line, "offset:");
		if (s == NULL)
			break;
		s += strlen("offset:");
		e = strchr(s, ';');
		if (e == NULL)
			break;
		*e = 0;
		data_offset = strtonum(s, 0, SSIZE_MAX, &errstr);
		if (errstr)
			data_offset = -1;
		break;
	}
	free(line);
	fclose(f);

	return (data_offset);
}

static int
kprobe_exp(char *exp, ssize_t *off1)
{
	ssize_t		 off;

	switch (*exp) {
	case '(': {
		char	*p, *o, *pa, *pb, c;
		ssize_t	 ia, ib;

		if ((p = strdup(exp)) == NULL)
			return (-1);
		o = p;
		*p++ = 0;
		pa = p;
		if (((p = strchr(pa, '+')) == NULL) &&
		    ((p = strchr(pa, '-')) == NULL)) {
			free(o);
			return (-1);
		}
		c = *p;
		*p++ = 0;
		pb = p;
		if ((p = strchr(p, ')')) == NULL) {
			warnx("%s: %s unbalanced parenthesis\n", __func__, exp);
			free(o);
			return (-1);
		}
		*p = 0;
		if (kprobe_exp(pa, &ia) == -1) {
			warnx("%s: %s is unresolved\n", __func__, pa);
			free(o);
			return (-1);
		}
		if (kprobe_exp(pb, &ib) == -1) {
			warnx("%s: %s is unresolved\n", __func__, pb);
			free(o);
			return (-1);
		}
		free(o);
		off = c == '+' ? ia + ib : ia - ib;
		break;
	}
	default: {
		const char	*errstr;

		off = strtonum(exp, INT32_MIN, INT32_MAX, &errstr);
		if (errstr == NULL)
			break;
		if ((off = quark_btf_offset(exp)) == -1) {
			warnx("%s: %s is unresolved\n", __func__, exp);
			return (-1);
		}
		break;
	}}

	*off1 = off;

	return (0);
}

static char *
kprobe_make_arg(struct kprobe_arg *karg)
{
	int	 i;
	ssize_t	 off;
	char	*p, **pp, *last, *kstr, *tokens[128], *arg_dsl;

	kstr = NULL;
	if ((arg_dsl = strdup(karg->arg_dsl)) == NULL)
		return (NULL);
	i = 0;
	for (p = strtok_r(arg_dsl, " ", &last);
	     p != NULL;
	     p = strtok_r(NULL, " ", &last)) {
		/* Last is sentinel */
		if (i == ((int)nitems(tokens) - 1)) {
			warnx("%s: too many tokens", __func__);
			free(arg_dsl);
			return (NULL);
		}
		tokens[i++] = p;
	}
	tokens[i] = NULL;
	if (asprintf(&kstr, "%%%s", karg->reg) == -1) {
		free(arg_dsl);
		return (NULL);
	}
	for (pp = tokens; *pp != NULL; pp++) {
		p = *pp;
		last = kstr;
		if (kprobe_exp(p, &off) == -1 ||
		    asprintf(&kstr, "+%zd(%s)", off, last) == -1) {
			free(arg_dsl);
			free(last);
			return (NULL);
		}
		free(last);
	}
	last = kstr;
	if (asprintf(&kstr, "%s=%s:%s", karg->name, last, karg->typ) == -1) {
		free(arg_dsl);
		free(last);
		return (NULL);
	}
	free(last);
	free(arg_dsl);

	return (kstr);
}

static char *
kprobe_build_string(struct kprobe *k)
{
	struct kprobe_arg	*karg;
	char			*p, *o, *a;
	int			 r;

	r = asprintf(&p, "%c:%s %s", k->is_kret ? 'r' : 'p', k->name,
	    k->target);
	if (r == -1)
		return (NULL);
	for (karg = k->args; karg->name != NULL; karg++) {
		a = kprobe_make_arg(karg);
		if (a == NULL) {
			free(p);
			return (NULL);
		}
		o = p;
		r = asprintf(&p, "%s %s", o, a);
		free(o);
		free(a);
		if (r == -1)
			return (NULL);
	}

	return (p);
}
#if 0
static int
kprobe_toggle(struct kprobe *k, int enable)
{
	int	fd;
	ssize_t n;

	if ((fd = open_tracing(O_WRONLY, "events/kprobes/%s/enable", k->name))
	    == -1)
		return (-1);
	if (enable)
		n = qwrite(fd, "1", 1);
	else
		n = qwrite(fd, "0", 1);
	close(fd);
	if (n == -1)
		return (-1);

	return (0);
}
#define kprobe_enable(_k)	kprobe_toggle((_k), 1)
#define kprobe_disable(_k)	kprobe_toggle((_k), 0)
#endif
static int
kprobe_uninstall(struct kprobe *k)
{
	char	buf[4096];
	ssize_t n;
	int	fd;

	if ((fd = open_tracing(O_WRONLY | O_APPEND, "kprobe_events")) == -1)
		return (-1);
	if (snprintf(buf, sizeof(buf), "-:%s", k->name) >=
	    (int)sizeof(buf)) {
		close(fd);
		return (-1);
	}
	n = qwrite(fd, buf, strlen(buf));
	close(fd);
	if (n == -1)
		return (-1);

	return (0);
}

/*
 * Builds the kprobe string and "installs" in tracefs, mapping to a perf ring is
 * later and belongs to kprobe_state. This separation makes library cleanup
 * easier.
 */
static int
kprobe_install(struct kprobe *k)
{
	int	 fd;
	ssize_t	 n;
	char	*kstr;

	if (kprobe_uninstall(k) == -1 && errno != ENOENT)
		warn("kprobe_uninstall");
	if ((kstr = kprobe_build_string(k)) == NULL)
		return (-1);
	if ((fd = open_tracing(O_WRONLY, "kprobe_events")) == -1) {
		free(kstr);
		return (-1);
	}
	n = qwrite(fd, kstr, strlen(kstr));
	close(fd);
	free(kstr);
	if (n == -1)
		return (-1);

	return (0);
}

static int
kprobe_init(void)
{
	struct kprobe	*k;
	int		 i = 0;

	while ((k = all_kprobes[i++]) != NULL) {
		if (kprobe_install(k) == -1)
			return (-1);
	}

	return (0);
}

static void
perf_attr_init(struct perf_event_attr *attr, int id)
{
	bzero(attr, sizeof(*attr));

	attr->type = PERF_TYPE_TRACEPOINT;
	attr->size = sizeof(*attr);
	attr->config = id;
	/* attr->config = PERF_COUNT_SW_DUMMY; */
	attr->sample_period = 1;	/* we want all events */
	attr->sample_type =
	    PERF_SAMPLE_TID		|
	    PERF_SAMPLE_TIME		|
	    PERF_SAMPLE_CPU		|
	    PERF_SAMPLE_RAW;

	/* attr->read_format = PERF_FORMAT_LOST; */
	/* attr->mmap2 */
	/* XXX Should we set clock in the child as well? XXX */
	attr->use_clockid = 1;
	attr->clockid = CLOCK_MONOTONIC_RAW;
	attr->disabled = 1;
}

static struct perf_group_leader *
perf_open_group_leader(int cpu)
{
	struct perf_group_leader	*pgl;
	int				 id;

	pgl = calloc(1, sizeof(*pgl));
	if (pgl == NULL)
		return (NULL);
	/* By putting EXEC on group leader we save one fd per cpu */
	if ((id = fetch_tracing_id("events/sched/sched_process_exec/id"))
	    == -1) {
		free(pgl);
		return (NULL);
	}
	perf_attr_init(&pgl->attr, id);
	/*
	 * We will still get task events as long as set comm, see
	 * perf_event_to_raw()
	 */
	pgl->attr.comm = 1;
	pgl->attr.comm_exec = 1;
	pgl->attr.sample_id_all = 1;		/* add sample_id to all types */
	pgl->attr.watermark = 1;
	pgl->attr.wakeup_watermark = (PERF_MMAP_PAGES * getpagesize()) / 10;;

	pgl->fd = perf_event_open(&pgl->attr, -1, cpu, -1, 0);
	if (pgl->fd == -1) {
		free(pgl);
		return (NULL);
	}
	if (perf_mmap_init(&pgl->mmap, pgl->fd) == -1) {
		close(pgl->fd);
		free(pgl);
		return (NULL);
	}
	pgl->cpu = cpu;
	id_to_sample_kind[id] = EXEC_SAMPLE;

	return (pgl);
}

static struct kprobe_state *
perf_open_kprobe(struct kprobe *k, int cpu, int group_fd)
{
	int			 id;
	char			 buf[MAXPATHLEN];
	struct kprobe_state	*ks;

	ks = calloc(1, sizeof(*ks));
	if (ks == NULL)
		return (NULL);
	if (snprintf(buf, sizeof(buf), "events/kprobes/%s/id", k->name)
	    >= (int)sizeof(buf)) {
		free(ks);
		return (errno = ENAMETOOLONG, NULL);
	}
	if ((id = fetch_tracing_id(buf)) == -1) {
		free(ks);
		return (NULL);
	}
	perf_attr_init(&ks->attr, id);
	ks->fd = perf_event_open(&ks->attr, -1, cpu, group_fd, 0);
	if (ks->fd == -1) {
		free(ks);
		return (NULL);
	}
	/* Output our records in the group_fd */
	if (ioctl(ks->fd, PERF_EVENT_IOC_SET_OUTPUT, group_fd) == -1) {
		close(ks->fd);
		free(ks);
		return (NULL);
	}
	ks->k = k;
	ks->cpu = cpu;
	ks->group_fd = group_fd;
	id_to_sample_kind[id] = ks->k->sample_kind;

	return (ks);
}

static int
sproc_status_line(struct quark_event *qev, const char *k, const char *v)
{
	const char		*errstr;

	if (*v == 0)
		return (0);

	if (!strcmp(k, "Pid")) {
		qev->pid = strtonum(v, 0, UINT32_MAX, &errstr);
		if (errstr != NULL)
			return (-1);
	} else if (!strcmp(k, "PPid")) {
		qev->proc_ppid = strtonum(v, 0, UINT32_MAX, &errstr);
		if (errstr != NULL)
			return (-1);
	} else if (!strcmp(k, "Uid")) {
		if (sscanf(v, "%d %d %d\n",
		    &qev->proc_uid, &qev->proc_euid, &qev->proc_suid) != 3)
			return (-1);
	} else if (!strcmp(k, "Gid")) {
		if (sscanf(v, "%d %d %d\n",
		    &qev->proc_gid, &qev->proc_egid, &qev->proc_sgid) != 3)
			return (-1);
	} else if (!strcmp(k, "CapInh")) {
		if (strtou64(&qev->proc_cap_inheritable, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapPrm")) {
		if (strtou64(&qev->proc_cap_permitted, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapEff")) {
		if (strtou64(&qev->proc_cap_effective, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapBnd")) {
		if (strtou64(&qev->proc_cap_bset, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapAmb")) {
		if (strtou64(&qev->proc_cap_ambient, v, 16) == -1)
			return (-1);
	}

	return (0);
}

static int
sproc_stat(struct quark_event *qev, int dfd)
{
	int			 fd, r, ret;
	char			*buf, *p;
	unsigned long long	 starttime;

	buf = NULL;
	ret = -1;

	if ((fd = openat(dfd, "stat", O_RDONLY)) == -1) {
		warn("%s: open stat", __func__);
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
	    "%*s "		/* (5) pgrp */
	    "%*s "		/* (6) session */
	    "%*s "		/* (7) tty_nr */
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
	    &starttime);

	if (r == 1) {
		qev->proc_time_boot =
		    hostinfo.boottime +
		    (((u64)starttime / (u64)hostinfo.hz) * NS_PER_S);

		ret = 0;
	}

cleanup:
	free(buf);
	close(fd);

	return (ret);
}

static int
sproc_status(struct quark_event *qev, int dfd)
{
	int			 fd, ret;
	FILE			*f;
	ssize_t			 n;
	size_t			 line_len;
	char			*line, *k, *v;

	if ((fd = openat(dfd, "status", O_RDONLY)) == -1) {
		warn("%s: open status", __func__);
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
			warnx("%s: bad line", __func__);
			ret = -1;
			break;
		}
		line[n - 1] = 0;
		k = line;
		v = strstr(line, ":\t");
		if (v == NULL) {
			warnx("%s: no `:\\t` found", __func__);
			ret = -1;
			break;
		}
		*v = 0;
		v += 2;
		if (sproc_status_line(qev, k, v) == -1) {
			warnx("%s: can't handle %s", __func__, k);
			ret = -1;
			break;
		}
	}
	free(line);
	fclose(f);

	return (ret);

}

static int
sproc_cmdline(struct quark_event *qev, int dfd)
{
	int	 fd;
	char	*buf;
	size_t	 buf_len, copy_len;

	if ((fd = openat(dfd, "cmdline", O_RDONLY)) == -1) {
		warn("%s: open cmdline", __func__);
		return (-1);
	}
	buf = load_file_nostat(fd, &buf_len);
	close(fd);
	if (buf == NULL)
		return (-1);
	copy_len = min(sizeof(qev->cmdline), buf_len);
	memcpy(qev->cmdline, buf, copy_len);
	free(buf);
	/* paranoia */
	qev->cmdline[copy_len - 1] = 0;
	qev->cmdline_len = copy_len;

	return (0);
}

static int
sproc_pid(struct quark_queue *qq, int pid, int dfd)
{
	struct quark_event	*qev;

	/*
	 * This allocates and inserts it into the cache in case it's not already
	 * there, if say, sproc_status() fails, process will be largely empty,
	 * still we know there was a process there somewhere.
	 */
	qev = event_cache_get(qq, pid, 1);
	if (qev == NULL)
		return (-1);

	if (sproc_status(qev, dfd) == 0 && sproc_stat(qev, dfd) == 0)
		qev->flags |= QUARK_F_PROC;

	/* QUARK_F_COMM */
	if (readlineat(dfd, "comm", qev->comm, sizeof(qev->comm)) > 0)
		qev->flags |= QUARK_F_COMM;
	/* QUARK_F_FILENAME */
	if (qreadlinkat(dfd, "exe", qev->filename, sizeof(qev->filename)) > 0)
		qev->flags |= QUARK_F_FILENAME;
	/* QUARK_F_CMDLINE */
	if (sproc_cmdline(qev, dfd) == 0)
		qev->flags |= QUARK_F_CMDLINE;
	/* QUARK_F_CWD */
	if (qreadlinkat(dfd, "cwd", qev->cwd, sizeof(qev->cwd)) > 0)
		qev->flags |= QUARK_F_CWD;

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
			warnx("%s: %s", f->fts_name, strerror(f->fts_errno));
		if (f->fts_info != FTS_D)
			continue;
		fts_set(tree, f, FTS_SKIP);

		if ((p = fts_children(tree, 0)) == NULL) {
			warn("fts_children");
			continue;
		}
		for (; p != NULL; p = p->fts_link) {
			int		 pid;
			const char	*errstr;

			if (p->fts_info == FTS_ERR || p->fts_info == FTS_NS) {
				warnx("%s: %s",
				    p->fts_name, strerror(p->fts_errno));
				continue;
			}
			if (p->fts_info != FTS_D || !isnumber(p->fts_name))
				continue;

			if ((dfd = openat(rootfd, p->fts_name, O_PATH)) == -1) {
				warn("openat %s", p->fts_name);
				continue;
			}
			pid = strtonum(p->fts_name, 1, UINT32_MAX, &errstr);
			if (errstr != NULL) {
				warnx("bad pid %s: %s", p->fts_name, errstr);
				goto next;
			}
			if (sproc_pid(qq, pid, dfd) == -1)
				warnx("can't scrape %s\n", p->fts_name);
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
		warnx("can't parse btime: %s", errstr);

	return (btime * NS_PER_S);
}

static int
hostinfo_init(void)
{
	unsigned int	hz;
	u64		boottime;
	ssize_t		dataoff;

	if ((hz = sysconf(_SC_CLK_TCK)) == (unsigned int)-1) {
		warn("%s: sysconf(_SC_CLK_TCK)", __func__);
		return (-1);
	}
	if ((boottime = fetch_boottime()) == 0) {
		warn("can't fetch btime");
		return (-1);
	}
	if ((dataoff = parse_probe_data_body_offset()) == -1) {
		warnx("%s: can't parse host probe data offset",
		    __func__);
		return (-1);
	}

	hostinfo.hz = hz;
	hostinfo.boottime = boottime;
	hostinfo.probe_data_body_offset = dataoff;

	return (0);
}

#define P(_f, ...)					\
	do {						\
		if (fprintf(_f, __VA_ARGS__) < 0)	\
			return (-1);			\
	} while(0)
static int
write_node_attr(FILE *f, struct raw_event *raw, char *key)
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
			warnx("%s: exec filename truncated", __func__);
		break;
	case RAW_WAKE_UP_NEW_TASK: {
		color = "orange";
		if (snprintf(label, sizeof(label), "NEW_TASK %d",
		    raw->pid) >= (int)sizeof(label))
			warnx("%s: snprintf", __func__);
		break;
	}
	case RAW_EXEC_CONNECTOR:
		color = "lightskyblue";
		if (snprintf(label, sizeof(label), "EXEC_CONNECTOR")
		    >= (int)sizeof(label))
			warnx("%s: exec_connector truncated", __func__);
		break;
	default:
		warnx("%s: %d unhandled\n", __func__, raw->type);
		color = "black";
		break;
	}
	P(f, "\"%s\" [label=\"%llu\\n%s\\npid %d\", fillcolor=%s];\n",
	    key, raw->time, label, raw->pid, color);

	return (0);
}

int
quark_dump_graphviz(struct quark_queue *qq, FILE *by_time, FILE *by_pidtime)
{
	struct raw_event	*raw, *left, *right;
	FILE			*f;
	char			 key[256];

	f = by_time;

	P(f, "digraph {\n");
	P(f, "node [style=filled, color=black];\n");
	RB_FOREACH(raw, raw_event_by_time, &qq->raw_event_by_time) {
		snprintf(key, sizeof(key), "%llu", raw->time);
		if (write_node_attr(f, raw, key) < 0)
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
		if (write_node_attr(f, raw, key) < 0)
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
#undef P

int
quark_queue_get_fds(struct quark_queue *qq, int *fds, int fds_len)
{
	struct perf_group_leader	*pgl;
	int				 nfds;

	if (TAILQ_EMPTY(&qq->perf_group_leaders))
		return (errno = EINVAL, -1);
	nfds = 0;
	TAILQ_FOREACH(pgl, &qq->perf_group_leaders, entry) {
		if (nfds == fds_len)
			return (errno = ENOBUFS, -1);
		*fds++ = pgl->fd;
		nfds++;
	}

	return (nfds);
}

int
quark_queue_block(struct quark_queue *qq)
{
	struct perf_group_leaders	*leaders;
	struct perf_group_leader	*pgl;
	struct pollfd			*fds;
	struct timespec			 ts;
	int				 i, nfds, r;

	leaders = &qq->perf_group_leaders;
	nfds = qq->num_perf_group_leaders;
	fds = calloc(sizeof(*fds), nfds);
	/* XXX TODO move this inside qq */
	if (fds == NULL)
		err(1, "calloc");
	i = 0;
	TAILQ_FOREACH(pgl, leaders, entry) {
		fds[i].fd = pgl->fd;
		fds[i].events = POLLIN | POLLRDHUP;
		i++;
	}
	ts.tv_sec = 0;
	ts.tv_nsec = MS_TO_NS(100); /* XXX hardcoded for now */
	r = ppoll(fds, nfds, &ts, NULL);
#if 0
	for (i = 0; i < nfds; i++)
		printf("fd%d events=0x%x\n", fds[i].fd, fds[i].revents);
#endif
	free(fds);

	return (r);
}

int
quark_queue_open(struct quark_queue *qq, int flags)
{
	int				 i;
	struct perf_group_leader	*pgl;
	struct kprobe			*k;
	struct kprobe_state		*ks;
	struct quark_event		*qev;

	bzero(qq, sizeof(*qq));

	TAILQ_INIT(&qq->perf_group_leaders);
	qq->num_perf_group_leaders = 0;
	TAILQ_INIT(&qq->kprobe_states);
	RB_INIT(&qq->raw_event_by_time);
	RB_INIT(&qq->raw_event_by_pidtime);
	RB_INIT(&qq->event_by_pid);
	TAILQ_INIT(&qq->event_gc);
	qq->flags = flags;
	qq->length = 0;
	qq->max_length = QUARK_QUEUE_MAXLENGTH;

	for (i = 0; i < get_nprocs_conf(); i++) {
		pgl = perf_open_group_leader(i);
		if (pgl == NULL)
			goto fail;
		TAILQ_INSERT_TAIL(&qq->perf_group_leaders, pgl, entry);
		qq->num_perf_group_leaders++;
	}

	i = 0;
	while ((k = all_kprobes[i++]) != NULL) {
		TAILQ_FOREACH(pgl, &qq->perf_group_leaders, entry) {
			ks = perf_open_kprobe(k, pgl->cpu, pgl->fd);
			if (ks == NULL)
				goto fail;
			TAILQ_INSERT_TAIL(&qq->kprobe_states, ks, entry);
		}
	}

	TAILQ_FOREACH(pgl, &qq->perf_group_leaders, entry) {
		/* XXX PERF_IOC_FLAG_GROUP see bugs */
		if (ioctl(pgl->fd, PERF_EVENT_IOC_RESET,
		    PERF_IOC_FLAG_GROUP) == -1) {
			warn("ioctl PERF_EVENT_IOC_RESET:");
			goto fail;
		}
		if (ioctl(pgl->fd, PERF_EVENT_IOC_ENABLE,
		    PERF_IOC_FLAG_GROUP) == -1) {
			warn("ioctl PERF_EVENT_IOC_ENABLE:");
			goto fail;
		}
	}

	/*
	 * Now that the rings are opened, we can scrape proc. If we would scrape
	 * before opening them, there would be a small window where we could
	 * lose new processes.
	 */
	if (sproc_scrape(qq) == -1) {
		warnx("can't scrape /proc");
		goto fail;
	}

	/*
	 * We want quark_get_events() to start by giving up a snapshot of
	 * everything we scraped, this snapshot will end up being spread into
	 * multiple quark_get_events() calls as there isn't enough storage for
	 * all of them. We need a way to know where we are in the snapshot.
	 */
	qev = RB_MIN(event_by_pid, &qq->event_by_pid);
	if (qev != NULL)
		qq->snap_pid = qev->pid;
	else
		qq->snap_pid = -1;

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
	struct perf_group_leader	*pgl;
	struct kprobe_state		*ks;
	struct raw_event		*raw;
	struct quark_event		*qev;

	/* Stop and close the perf rings */
	while ((pgl = TAILQ_FIRST(&qq->perf_group_leaders)) != NULL) {
		/* XXX PERF_IOC_FLAG_GROUP see bugs */
		if (pgl->fd != -1) {
			if (ioctl(pgl->fd, PERF_EVENT_IOC_DISABLE,
			    PERF_IOC_FLAG_GROUP) == -1)
				warnx("ioctl PERF_EVENT_IOC_DISABLE:");
			close(pgl->fd);
		}
		if (pgl->mmap.metadata != NULL)
			if (munmap(pgl->mmap.metadata, pgl->mmap.mapped_size) != 0)
				warn("munmap");
		TAILQ_REMOVE(&qq->perf_group_leaders, pgl, entry);
		free(pgl);
	}
	/* Clean up all state allocated to kprobes */
	while ((ks = TAILQ_FIRST(&qq->kprobe_states)) != NULL) {
		if (ks->fd != -1)
			close(ks->fd);
		TAILQ_REMOVE(&qq->kprobe_states, ks, entry);
		free(ks);
	}
	/* Clean up all allocated raw events */
	while ((raw = RB_ROOT(&qq->raw_event_by_time)) != NULL) {
		raw_event_remove(qq, raw);
		raw_event_free(raw);
	}
	if (!RB_EMPTY(&qq->raw_event_by_pidtime))
		warnx("raw_event trees not empty");
	/* Clean up all cached quark_events */
	while ((qev = RB_ROOT(&qq->event_by_pid)) != NULL)
		event_cache_delete(qq, qev);
}

enum agg_kind {
	AGG_NONE,		/* Can't aggregate, must be zero */
	AGG_SINGLE,		/* Can aggregate only one value */
	AGG_MULTI		/* Can aggregate multiple values */
};
                  /* dst */      /* src */
u8 agg_matrix[RAW_NUM_TYPES][RAW_NUM_TYPES] = {
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

static int
can_aggregate(struct raw_event *dst, struct raw_event *src)
{
	int			 kind;
	struct raw_event	*agg;

	/* Different pids can't aggregate */
	if (dst->pid != src->pid)
		return (0);

	if (dst->type >= RAW_NUM_TYPES || src->type >= RAW_NUM_TYPES ||
	    dst->type < 1 || src->type < 1) {
		warnx("type out of bounds dst=%d src=%d\n",
		    dst->type, src->type);
		return (0);
	}

	kind = agg_matrix[dst->type][src->type];

	switch (kind) {
	case AGG_NONE:
		return (0);
	case AGG_MULTI:
		return (1);
	case AGG_SINGLE:
		TAILQ_FOREACH(agg, &dst->agg_queue, agg_entry) {
			if (agg->type == src->type)
				return (0);
		}
		return (1);
	default:
		warnx("unhandle agg kind %d\n", kind);
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
		if (!can_aggregate(min, next))
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
	int				 empty_rings, num_rings, npop;
	struct perf_group_leader	*pgl;
	struct perf_event		*ev;
	struct raw_event		*raw;

	num_rings = qq->num_perf_group_leaders;
	npop = 0;

	/*
	 * We stop if the queue is full, or if we see all perf ring buffers
	 * empty.
	 */
	while (qq->length < qq->max_length) {
		empty_rings = 0;
		TAILQ_FOREACH(pgl, &qq->perf_group_leaders, entry) {
			ev = perf_mmap_read(&pgl->mmap);
			if (ev == NULL) {
				empty_rings++;
				continue;
			}
			empty_rings = 0;
			raw = perf_event_to_raw(qq, ev);
			if (raw != NULL) {
				raw_event_insert(qq, raw);
				npop++;
			}
			perf_mmap_consume(&pgl->mmap);
		}
		if (empty_rings == num_rings)
			break;
	}

	return (npop);
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
			struct quark_event	*qsev;

			qsev = event_cache_get(qq, qq->snap_pid, 0);
			if (qsev == NULL) {
				warnx("event vanished during snapshot, "
				    "this is a bug\n");
				qq->snap_pid = -1;
				/* errno set by cache_lookup */
				return (-1);
			}
			/* Copy out to user */
			event_copy_out(qevs, qsev, QUARK_EV_SNAPSHOT);
			qsev = RB_NEXT(event_by_pid, &qq->event_by_pid, qsev);
			/* Are we done with the snapshot? If not, record next */
			if (qsev == NULL)
				qq->snap_pid = -1;
			else
				qq->snap_pid = qsev->pid;
		} else {
			raw = quark_queue_pop_raw(qq);
			if (raw == NULL)
				break;
			if (raw_event_to_quark_event(qq, raw, qevs) == -1) {
				raw_event_free(raw);
				warnx("raw_event_to_quark_event");
				continue;
			}
			raw_event_free(raw);
		}
		got++;
		qevs++;
	}

	/* GC all processes that exited after some grace time */
	event_cache_gc(qq);

	return (got);
}

int
quark_init(void)
{
	if (hostinfo_init() == -1) {
		warn("%s: can't grab hostinfo", __func__);
		return (-1);
	}
	if (quark_btf_init() == -1) {
		warnx("%s: can't initialize btf", __func__);
		return (-1);
	}
	if (kprobe_init() == -1) {
		warnx("%s: can't initialize kprobes", __func__);
		return (-1);
	}

	return (0);
}

int
quark_close(void)
{

	struct kprobe	*k;
	int		 i;

	i = 0;
	while ((k = all_kprobes[i++]) != NULL) {
		(void)kprobe_uninstall(k);
	}

	return (0);
}
