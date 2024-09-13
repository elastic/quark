// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "quark.h"

#define PERF_MMAP_PAGES		16		/* Must be power of 2 */

struct perf_sample_id {
	u32	pid;
	u32	tid;
	u64	time;		/* See raw_event_insert() */
	u32	cpu;
	u32	cpu_unused;
};

struct perf_record_fork {
	struct perf_event_header	header;
	u32				pid;
	u32				ppid;
	u32				tid;
	u32				ptid;
	u64				time;
	struct perf_sample_id		sample_id;
};

struct perf_record_exit {
	struct perf_event_header	header;
	u32				pid;
	u32				ppid;
	u32				tid;
	u32				ptid;
	u64				time;
	struct perf_sample_id		sample_id;
};

struct perf_record_comm {
	struct perf_event_header	header;
	u32				pid;
	u32				tid;
	char				comm[];
	/* followed by sample_id */
};

/*
 * Kernels might actually have a different common area, so far we only
 * need common_type, so hold onto that
 */
struct perf_sample_data_hdr {
	/* this is the actual id from tracefs eg: sched_process_exec/id */
	u16	 common_type;
	/* ... */
};

struct perf_sample_data_loc {
	u16	offset;
	u16	size;
};

struct perf_record_sample {
	struct perf_event_header	header;
	struct perf_sample_id		sample_id;
	u32				data_size;
	char				data[];
};

struct perf_record_lost {
	struct perf_event_header	header;
	u64				id;
	u64				lost;
	struct perf_sample_id		sample_id;
};

struct perf_event {
	union {
		struct perf_event_header	header;
		struct perf_record_fork		fork;
		struct perf_record_exit		exit;
		struct perf_record_comm		comm;
		struct perf_record_sample	sample;
		struct perf_record_lost		lost;
	};
};

struct perf_mmap {
	struct perf_event_mmap_page	*metadata;
	size_t				 mapped_size;
	size_t				 data_size;
	size_t				 data_mask;
	u8				*data_start;
	u64				 data_tmp_tail;
	u8				 wrapped_event_buf[4096] __aligned(8);
};

struct perf_group_leader {
	TAILQ_ENTRY(perf_group_leader)	 entry;
	int				 fd;
	int				 cpu;
	struct perf_event_attr		 attr;
	struct perf_mmap		 mmap;
};

/*
 * Forbid padding on samples/wire structures
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wpadded"

struct exec_sample {
	struct perf_sample_data_loc	filename;
	s32				pid;
	s32				old_pid;
};

#define MAX_PWD		7

/* Sorted by alignment restriction, 64->32->16->8 */
struct task_sample {
	/* 64bit */
	u64	probe_ip;
	u64	cap_inheritable;
	u64	cap_permitted;
	u64	cap_effective;
	u64	cap_bset;
	u64	cap_ambient;
	u64	start_boottime;
	u64	tty_addr;
	u64	root_k;
	u64	mnt_root_k;
	u64	mnt_mountpoint_k;
	u64	pwd_k[MAX_PWD];
	/* 32bit */
	struct perf_sample_data_loc root_s;
	struct perf_sample_data_loc mnt_root_s;
	struct perf_sample_data_loc mnt_mountpoint_s;
	struct perf_sample_data_loc pwd_s[MAX_PWD];
	struct perf_sample_data_loc comm;
	u32	uid;
	u32	gid;
	u32	suid;
	u32	sgid;
	u32	euid;
	u32	egid;
	u32	pgid;
	u32	sid;
	u32	pid;
	u32	tid;
	u32	ppid;
	s32	exit_code;
	u32	tty_major;
	u32	tty_minor_start;
	u32	tty_minor_index;
	/* 16bit */
	/* 8bit */
};

struct exec_connector_sample {
	struct task_sample		task_sample;	/* must be 8 byte aligned */
	/* 64bit */
	u64				argc;
	u64				stack[60];	/* sync with kprobe_defs */
};

#pragma GCC diagnostic pop

/*
 * End samples/wire/ structures
 */

struct kprobe_state {
	TAILQ_ENTRY(kprobe_state)	 entry;
	struct kprobe			*k;
	struct perf_event_attr		 attr;
	int				 fd;
	int				 cpu;
	int				 group_fd;
};

struct kprobe_arg {
	const char	*name;
	const char	*reg;
	const char	*typ;
	const char	*arg_dsl;
};

struct kprobe {
	const char		*target;
	int			 sample_kind;
	int			 is_kret;
	struct kprobe_arg	 args[];
};

struct path_ctx {
	char	*root;
	u64	 root_k;
	char	*mnt_root;
	u64	 mnt_root_k;
	char	*mnt_mountpoint;
	u64	 mnt_mountpoint_k;
	struct {
		char	*pwd;
		u64	 pwd_k;
	} pwd[MAX_PWD];
};

/*
 * Kprobe sample formats
 */
enum sample_kinds {
	EXEC_SAMPLE = 1,
	WAKE_UP_NEW_TASK_SAMPLE,
	EXIT_THREAD_SAMPLE,
	EXEC_CONNECTOR_SAMPLE
};

/*
 * The actual probe definitions, they're too big and ugly so they get a separate
 * file
 */
#include "kprobe_defs.h"

/*
 * Queue backend state
 */
TAILQ_HEAD(perf_group_leaders, perf_group_leader);
TAILQ_HEAD(kprobe_states, kprobe_state);

#define MAX_SAMPLE_IDS		4096		/* id_to_sample_kind map */

struct kprobe_queue {
	struct perf_group_leaders	 perf_group_leaders;
	int				 num_perf_group_leaders;
	struct kprobe_states		 kprobe_states;
	ssize_t				 data_offset; /* body data off within a probe */
	int				 qid;
	/* matches each sample event to a kind like EXEC_SAMPLE, FOO_SAMPLE */
	u8				 id_to_sample_kind[MAX_SAMPLE_IDS];
};

static int	kprobe_queue_populate(struct quark_queue *);
static int	kprobe_queue_update_stats(struct quark_queue *);
static void	kprobe_queue_close(struct quark_queue *);

struct quark_queue_ops queue_ops_kprobe = {
	.open	      = kprobe_queue_open,
	.populate     = kprobe_queue_populate,
	.update_stats = kprobe_queue_update_stats,
	.close	      = kprobe_queue_close,
};

static char *
str_of_dataloc(struct perf_record_sample *sample,
    struct perf_sample_data_loc *data_loc)
{
	return (sample->data + data_loc->offset);
}

static inline int
sample_kind_of_id(struct kprobe_queue *kqq, int id)
{
	if (unlikely(id <= 0 || id >= MAX_SAMPLE_IDS)) {
		warnx("%s: invalid id %d", __func__, id);
		return (errno = ERANGE, -1);
	}

	return (kqq->id_to_sample_kind[id]);
}

static inline void *
sample_data_body(struct kprobe_queue *kqq, struct perf_record_sample *sample)
{
	return (sample->data + kqq->data_offset);
}

static inline int
sample_data_id(struct perf_record_sample *sample)
{
	struct perf_sample_data_hdr *h = (struct perf_sample_data_hdr *)sample->data;
	return (h->common_type);
}

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

static int
qstr_copy_data_loc(struct qstr *qstr,
    struct perf_record_sample *sample, struct perf_sample_data_loc *data_loc)
{
	/* size includes NUL */
	if (qstr_ensure(qstr, data_loc->size) == -1)
		return (-1);
	memcpy(qstr->p, sample->data + data_loc->offset, data_loc->size);

	return (data_loc->size);
}

static void
task_sample_to_raw_task(struct kprobe_queue *kqq, int kind,
    struct perf_record_sample *sample, struct raw_task *task)
{
	struct task_sample	*w = sample_data_body(kqq, sample);
	struct path_ctx		 pctx;
	int			 i;

	task->cap_inheritable = w->cap_inheritable;
	task->cap_permitted = w->cap_permitted;
	task->cap_effective = w->cap_effective;
	task->cap_bset = w->cap_bset;
	task->cap_ambient = w->cap_ambient;
	task->start_boottime = w->start_boottime;
	task->uid = w->uid;
	task->gid = w->gid;
	task->suid = w->suid;
	task->sgid = w->sgid;
	task->euid = w->euid;
	task->egid = w->egid;
	task->pgid = w->pgid;
	task->sid = w->sid;
	task->ppid = w->ppid;
	if (w->tty_addr) {
		task->tty_major = w->tty_major;
		task->tty_minor = w->tty_minor_start + w->tty_minor_index;
	}
	/* cwd below */
	strlcpy(task->comm, str_of_dataloc(sample, &w->comm),
	    sizeof(task->comm));
	if (kind == EXIT_THREAD_SAMPLE) {
		task->exit_code = (w->exit_code >> 8) & 0xff;
		task->exit_time_event = sample->sample_id.time;
		qstr_strcpy(&task->cwd, "(exited)");
		/* No cwd on exit */
		return;
	}

	task->exit_code = -1;
	task->exit_time_event = 0;

	/* Consider moving all this inside build_path() */
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
	if (build_path(&pctx, &task->cwd) == -1)
		warn("can't build path");
}

static struct raw_event *
perf_sample_to_raw(struct quark_queue *qq, struct perf_record_sample *sample)
{
	struct kprobe_queue	*kqq = qq->queue_be;
	int			 id, kind;
	ssize_t			 n;
	struct raw_event	*raw = NULL;

	id = sample_data_id(sample);
	kind = sample_kind_of_id(kqq, id);

	switch (kind) {
	case EXEC_SAMPLE: {
		struct exec_sample *exec = sample_data_body(kqq, sample);
		if ((raw = raw_event_alloc(RAW_EXEC)) == NULL)
			return (NULL);
		n = qstr_copy_data_loc(&raw->exec.filename, sample, &exec->filename);
		if (n == -1)
			warnx("can't copy exec filename");
		break;
	}
	case WAKE_UP_NEW_TASK_SAMPLE: /* FALLTHROUGH */
	case EXIT_THREAD_SAMPLE: {
		struct task_sample	*w = sample_data_body(kqq, sample);
		int			 raw_type;
		/*
		 * ev->sample.sample_id.pid is the parent, if the new task has
		 * the same pid as it, then this is a thread event
		 */
		if ((qq->flags & QQ_THREAD_EVENTS) == 0
		    && w->pid != w->tid)
			return (NULL);
		raw_type = kind == WAKE_UP_NEW_TASK_SAMPLE ?
		    RAW_WAKE_UP_NEW_TASK : RAW_EXIT_THREAD;
		if ((raw = raw_event_alloc(raw_type)) == NULL)
			return (NULL);
		/*
		 * Cheat, make it look like a child event
		 */
		if (raw_type == RAW_WAKE_UP_NEW_TASK) {
			raw->pid = w->pid;
			raw->tid = w->tid;
		}
		task_sample_to_raw_task(kqq, kind, sample, &raw->task);
		break;
	}
	case EXEC_CONNECTOR_SAMPLE: {
		char				*start, *p, *end;
		int				 i;
		struct exec_connector_sample	*exec_sample = sample_data_body(kqq, sample);
		struct raw_exec_connector	*exec;

		if ((raw = raw_event_alloc(RAW_EXEC_CONNECTOR)) == NULL)
			return (NULL);
		exec = &raw->exec_connector;

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
		task_sample_to_raw_task(kqq, kind, sample, &exec->task);
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
		if ((raw = raw_event_alloc(RAW_COMM)) == NULL)
			return (NULL);
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
	if (mm->metadata == MAP_FAILED)
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
parse_data_offset(void)
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
kprobe_exp(char *exp, ssize_t *off1, struct quark_btf *qbtf)
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
		if (kprobe_exp(pa, &ia, qbtf) == -1) {
			warnx("%s: %s is unresolved\n", __func__, pa);
			free(o);
			return (-1);
		}
		if (kprobe_exp(pb, &ib, qbtf) == -1) {
			warnx("%s: %s is unresolved\n", __func__, pb);
			free(o);
			return (-1);
		}
		off = c == '+' ? ia + ib : ia - ib;

		/* Jump over `)` */
		p++;
		/* Walk the original expression, there more after `)` */
		exp += p - o;
		free(o);
		/* If there is a dot after `)`, recurse */
		if (*exp++ == '.') {
			if (kprobe_exp(exp, &ia, qbtf) == -1) {
				warnx("%s: %s is unresolved\n", __func__, exp);
				return (-1);
			}
			off += ia;
		}
		break;
	}
	default: {
		const char	*errstr;

		off = strtonum(exp, INT32_MIN, INT32_MAX, &errstr);
		if (errstr == NULL)
			break;
		if ((off = quark_btf_offset(qbtf, exp)) == -1) {
			warnx("%s: %s is unresolved\n", __func__, exp);
			return (-1);
		}
		break;
	}}

	*off1 = off;

	return (0);
}

/*
 * Old kernels have some offsets in different structures, not just under a
 * different name(see btf_alternatives{}). We handle those differences here
 * by detecting it at runtime and issuing the correct kprobe_arg.
 */
static struct kprobe_arg *
kprobe_kludge_arg(struct kprobe *k, struct kprobe_arg *karg,
    struct quark_btf *qbtf)
{
	/*
	 * For TASK_SAMPLE, pgid and sid depend on fetching pids, which in newer
	 * kernels are deep within signal_struct, but older kernels have it
	 * within task_struct. So if signal_struct.pids exists, it's the "new"
	 * version.
	 */
	if ((k == &kp_wake_up_new_task ||
	    k == &kp_exit ||
	    k == &kp_exec_connector) &&
	    !strcmp(karg->name, "pgid")) {
		if (quark_btf_offset(qbtf, "signal_struct.pids") == -1)
			return (&ka_task_old_pgid);

		return (&ka_task_new_pgid);
	}

	if ((k == &kp_wake_up_new_task ||
	    k == &kp_exit ||
	    k == &kp_exec_connector) &&
	    !strcmp(karg->name, "sid")) {
		if (quark_btf_offset(qbtf, "signal_struct.pids") == -1)
			return (&ka_task_old_sid);

		return (&ka_task_new_sid);
	}

	/* No kludges found, carry on */
	return (karg);
}

static char *
kprobe_make_arg(struct kprobe *k, struct kprobe_arg *karg,
    struct quark_btf *qbtf)
{
	int	 i;
	ssize_t	 off;
	char	*p, **pp, *last, *kstr, *tokens[128], *arg_dsl;

	karg = kprobe_kludge_arg(k, karg, qbtf);

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
		if (kprobe_exp(p, &off, qbtf) == -1 ||
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

static void
kprobe_tracefs_name(struct kprobe *k, u64 qid, char *buf, size_t len)
{
	snprintf(buf, len, "quark_%s_%llu_%llu", k->target, (u64)getpid(), qid);
}

static char *
kprobe_build_string(struct kprobe *k, char *name, struct quark_btf *qbtf)
{
	struct kprobe_arg	*karg;
	char			*p, *o, *a;
	int			 r;

	r = asprintf(&p, "%c:%s %s", k->is_kret ? 'r' : 'p',
	    name, k->target);
	if (r == -1)
		return (NULL);
	for (karg = k->args; karg->name != NULL; karg++) {
		a = kprobe_make_arg(k, karg, qbtf);
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

static int
kprobe_uninstall(struct kprobe *k, u64 qid)
{
	char	buf[4096];
	ssize_t n;
	int	fd;
	char	fsname[MAXPATHLEN];

	kprobe_tracefs_name(k, qid, fsname, sizeof(fsname));

	if ((fd = open_tracing(O_WRONLY | O_APPEND, "kprobe_events")) == -1)
		return (-1);
	if (snprintf(buf, sizeof(buf), "-:%s", fsname) >=
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
kprobe_install(struct kprobe *k, u64 qid, struct quark_btf *qbtf)
{
	int	 fd;
	ssize_t	 n;
	char	*kstr;
	char	 fsname[MAXPATHLEN];

	kprobe_tracefs_name(k, qid, fsname, sizeof(fsname));

	if (kprobe_uninstall(k, qid) == -1 && errno != ENOENT)
		warn("kprobe_uninstall");
	if ((kstr = kprobe_build_string(k, fsname, qbtf)) == NULL)
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
kprobe_install_all(u64 qid)
{
	int			 i, r;
	struct quark_btf	*qbtf;

	if ((qbtf = quark_btf_open(NULL, NULL)) == NULL) {
		warnx("%s: can't initialize btf", __func__);
		return (-1);
	}

	r = 0;
	for (i = 0; all_kprobes[i] != NULL; i++) {
		if (kprobe_install(all_kprobes[i], qid, qbtf) == -1) {
			warnx("%s: kprobe %s failed", __func__,
			    all_kprobes[i]->target);
			/* Uninstall the ones that succeeded */
			while (--i >= 0)
				kprobe_uninstall(all_kprobes[i], qid);

			r = -1;
			break;
		}
	}
	quark_btf_close(qbtf);

	return (r);
}

static void
kprobe_uninstall_all(u64 qid)
{
	int	i;

	for (i = 0; all_kprobes[i] != NULL; i++)
		kprobe_uninstall(all_kprobes[i], qid);
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
	attr->clockid = CLOCK_MONOTONIC;
	attr->disabled = 1;
}

static struct perf_group_leader *
perf_open_group_leader(struct kprobe_queue *kqq, int cpu)
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
	kqq->id_to_sample_kind[id] = EXEC_SAMPLE;

	return (pgl);
}

static struct kprobe_state *
perf_open_kprobe(struct kprobe_queue *kqq, struct kprobe *k,
    u64 qid, int cpu, int group_fd)
{
	int			 id;
	char			 buf[MAXPATHLEN];
	char			 fsname[MAXPATHLEN];
	struct kprobe_state	*ks;

	kprobe_tracefs_name(k, qid, fsname, sizeof(fsname));

	ks = calloc(1, sizeof(*ks));
	if (ks == NULL)
		return (NULL);
	if (snprintf(buf, sizeof(buf), "events/kprobes/%s/id",
	    fsname) >= (int)sizeof(buf)) {
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
	kqq->id_to_sample_kind[id] = ks->k->sample_kind;

	return (ks);
}

int
kprobe_queue_open(struct quark_queue *qq)
{
	struct kprobe_queue		*kqq;
	struct perf_group_leader	*pgl;
	struct kprobe			*k;
	struct kprobe_state		*ks;
	struct epoll_event		 ev;
	ssize_t				 data_offset;
	int				 i;
	u64				 qid;
	static u64			 qids;

	if ((qq->flags & QQ_KPROBE) == 0)
		return (errno = ENOTSUP, -1);

	qid = __atomic_fetch_add(&qids, 1, __ATOMIC_RELAXED);
	if ((data_offset = parse_data_offset()) == -1)
		goto fail;
	if (kprobe_install_all(qid) == -1)
		goto fail;
	if ((kqq = calloc(1, sizeof(*kqq))) == NULL)
		goto fail;

	TAILQ_INIT(&kqq->perf_group_leaders);
	kqq->num_perf_group_leaders = 0;
	TAILQ_INIT(&kqq->kprobe_states);
	kqq->qid = qid;
	kqq->data_offset = data_offset;
	qq->queue_be = kqq;

	for (i = 0; i < get_nprocs_conf(); i++) {
		pgl = perf_open_group_leader(kqq, i);
		if (pgl == NULL)
			goto fail;
		TAILQ_INSERT_TAIL(&kqq->perf_group_leaders, pgl, entry);
		kqq->num_perf_group_leaders++;
	}

	i = 0;
	while ((k = all_kprobes[i++]) != NULL) {
		TAILQ_FOREACH(pgl, &kqq->perf_group_leaders, entry) {
			ks = perf_open_kprobe(kqq, k, kqq->qid, pgl->cpu, pgl->fd);
			if (ks == NULL)
				goto fail;
			TAILQ_INSERT_TAIL(&kqq->kprobe_states, ks, entry);
		}
	}

	TAILQ_FOREACH(pgl, &kqq->perf_group_leaders, entry) {
		/* XXX PERF_IOC_FLAG_GROUP see bugs */
		if (ioctl(pgl->fd, PERF_EVENT_IOC_RESET,
		    PERF_IOC_FLAG_GROUP) == -1) {
			warn("ioctl PERF_EVENT_IOC_RESET");
			goto fail;
		}
		if (ioctl(pgl->fd, PERF_EVENT_IOC_ENABLE,
		    PERF_IOC_FLAG_GROUP) == -1) {
			warn("ioctl PERF_EVENT_IOC_ENABLE");
			goto fail;
		}
	}

	qq->epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (qq->epollfd == -1) {
		warn("epoll_create1");
		goto fail;
	}
	TAILQ_FOREACH(pgl, &kqq->perf_group_leaders, entry) {
		bzero(&ev, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = pgl->fd;
		if (epoll_ctl(qq->epollfd, EPOLL_CTL_ADD, pgl->fd, &ev) == -1) {
			warn("epoll_ctl");
			goto fail;
		}
	}

	qq->queue_ops = &queue_ops_kprobe;

	return (0);

fail:
	kprobe_queue_close(qq);

	return (-1);
}

static int
kprobe_queue_populate(struct quark_queue *qq)
{
	struct kprobe_queue		*kqq = qq->queue_be;
	int				 empty_rings, num_rings, npop;
	struct perf_group_leader	*pgl;
	struct perf_event		*ev;
	struct raw_event		*raw;

	num_rings = kqq->num_perf_group_leaders;
	npop = 0;

	/*
	 * We stop if the queue is full, or if we see all perf ring buffers
	 * empty.
	 */
	while (qq->length < qq->max_length) {
		empty_rings = 0;
		TAILQ_FOREACH(pgl, &kqq->perf_group_leaders, entry) {
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

static int
kprobe_queue_update_stats(struct quark_queue *qq)
{
	/* NADA */
	return (0);
}

static void
kprobe_queue_close(struct quark_queue *qq)
{
	struct kprobe_queue		*kqq = qq->queue_be;
	struct perf_group_leader	*pgl;
	struct kprobe_state		*ks;

	if (kqq != NULL) {
		/* Stop and close the perf rings */
		while ((pgl = TAILQ_FIRST(&kqq->perf_group_leaders)) != NULL) {
			/* XXX PERF_IOC_FLAG_GROUP see bugs */
			if (pgl->fd != -1) {
				if (ioctl(pgl->fd, PERF_EVENT_IOC_DISABLE,
				    PERF_IOC_FLAG_GROUP) == -1)
					warnx("ioctl PERF_EVENT_IOC_DISABLE:");
				close(pgl->fd);
			}
			if (pgl->mmap.metadata != NULL) {
				if (munmap(pgl->mmap.metadata,
				    pgl->mmap.mapped_size) != 0)
					warn("munmap");
			}
			TAILQ_REMOVE(&kqq->perf_group_leaders, pgl, entry);
			free(pgl);
		}
		/* Clean up all state allocated to kprobes */
		while ((ks = TAILQ_FIRST(&kqq->kprobe_states)) != NULL) {
			if (ks->fd != -1)
				close(ks->fd);
			TAILQ_REMOVE(&kqq->kprobe_states, ks, entry);
			free(ks);
		}

		kprobe_uninstall_all(kqq->qid);
		free(kqq);
		kqq = NULL;
		qq->queue_be = NULL;
	}
	/* Clean up epoll instance */
	if (qq->epollfd != -1) {
		close(qq->epollfd);
		qq->epollfd = -1;
	}
}
