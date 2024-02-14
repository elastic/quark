#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "quark.h"

#define PERF_MMAP_PAGES		16		/* Must be power of 2 */
#define RAW_HOLD_MAXTIME	MS_TO_NS(1000)	/* XXX hardcoded for now XXX */
#define RAW_HOLD_MAXNODES	10000		/* XXX hardcoded for now XXX */
#define AGE(_ts, _now) 		((_ts) > (_now) ? 0 : (_now) - (_ts))
#define MAX_SAMPLE_IDS		4096		/* id_to_sample_kind map */

static void	xfprintf(FILE *, const char *, ...) __attribute__((format(printf, 2, 3)));
static int	open_tracing(int, const char *, ...) __attribute__((format(printf, 2, 3)));
static int	raw_event_by_time_cmp(struct raw_event *, struct raw_event *);
static int	raw_event_by_pidtime_cmp(struct raw_event *, struct raw_event *);

/* matches each sample event to a kind like EXEC_SAMPLE, FOO_SAMPLE */
u8	id_to_sample_kind[MAX_SAMPLE_IDS];

/*
 * This is the offset from the common area of a probe to the body. It is almost
 * always 8, but some older redhat kernels are different.
 */
ssize_t	quark_probe_data_body_offset;

struct kprobe kp_wake_up_new_task = {
	"quark_wake_up_new_task",
	"wake_up_new_task",
	WAKE_UP_NEW_TASK_SAMPLE,
	0,
{
	{ "uid",		"di", "u32", "task_struct.cred cred.uid"		},
	{ "gid",		"di", "u32", "task_struct.cred cred.gid"		},
	{ "suid",		"di", "u32", "task_struct.cred cred.suid"		},
	{ "sgid",		"di", "u32", "task_struct.cred cred.sgid"		},
	{ "euid",		"di", "u32", "task_struct.cred cred.euid"		},
	{ "egid",		"di", "u32", "task_struct.cred cred.egid"		},
	{ "cap_inheritable",	"di", "u64", "task_struct.cred cred.cap_inheritable"	},
	{ "cap_permitted",	"di", "u64", "task_struct.cred cred.cap_permitted"	},
	{ "cap_effective",	"di", "u64", "task_struct.cred cred.cap_effective"	},
	{ "cap_bset",		"di", "u64", "task_struct.cred cred.cap_bset"		},
	{ "cap_ambient",	"di", "u64", "task_struct.cred cred.cap_ambient"	},
	{ "pid",		"di", "u32", "task_struct.tgid"				},
	{ "tid",		"di", "u32", "task_struct.pid"				},
	{ "start_time",		"di", "u64", "task_struct.start_time"			},
	{ "start_boottime",	"di", "u64", "task_struct.start_boottime"		},
	{ NULL,			NULL, NULL,  NULL					}
}
};

struct kprobe *all_kprobes[] = {
	&kp_wake_up_new_task,
	NULL
};

RB_PROTOTYPE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);
RB_GENERATE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);

RB_PROTOTYPE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);
RB_GENERATE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);

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
	default:
		break;
	}

	while ((aux = TAILQ_FIRST(&raw->agg_queue)) != NULL) {
		TAILQ_REMOVE(&raw->agg_queue, aux, agg_entry);
		free(aux);
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

static inline int
raw_event_expired(struct raw_event *raw, u64 now)
{
	/* XXX hardcoded for now XXX */
	return (raw_event_age(raw, now) >= (u64)RAW_HOLD_MAXTIME);
}

static void
raw_event_dump(struct raw_event *raw, int is_agg)
{
	struct raw_event	*agg;
	char			*header;

	header = is_agg ? "\t++" : "->";

	switch (raw->type) {
	case RAW_WAKE_UP_NEW_TASK: {
		struct wake_up_new_task_sample *w = &raw->wake_up_new_task;

		printf("%swake_up_new_task (%d)\n\t", header, raw->pid);
		printf("pid=%d tid=%d uid=%d gid=%d suid=%d sgid=%d euid=%d egid=%d\n",
		    w->pid, w->tid, w->uid, w->gid, w->suid, w->sgid, w->euid, w->egid);
		printf("\tstart_time=%llu start_boottime=%llu\n", w->start_time, w->start_boottime);
		printf("\tcap_inheritable=0x%llx cap_permitted=0x%llx cap_effective=0x%llx\n"
		    "\tcap_bset=0x%llx cap_ambient=0x%llx\n",
		    w->cap_inheritable, w->cap_permitted, w->cap_effective,
		    w->cap_bset, w->cap_ambient);
		TAILQ_FOREACH(agg, &raw->agg_queue, agg_entry) {
			raw_event_dump(agg, 1);
		}
		break;
	}
	case RAW_EXEC:
		printf("%sexec (%d)\n\tfilename=%s\n",
		    header, raw->pid, raw->exec.filename.p);
		break;
	case RAW_EXIT:
		printf("%sexit (%d)\n", header, raw->pid);
		break;
	default:
		printf("->Unhandled(type %d, pid %d)\n", raw->type, raw->pid);
		break;
	}
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
	return (sample->data + quark_probe_data_body_offset);
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
static struct raw_event *
perf_sample_to_raw(struct quark_queue *qq, struct perf_record_sample *sample)
{
	int			 id;
	ssize_t			 n;
	struct raw_event	*raw = NULL;

	id = sample_data_id(sample);

	switch (sample_kind_of_id(id)) {
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
	case WAKE_UP_NEW_TASK_SAMPLE: {
		struct wake_up_new_task_sample *w = sample_data_body(sample);
		/*
		 * ev->sample.sample_id.pid is the parent, if the new task has
		 * the same pid as it, then this is a thread event
		 */
		if ((qq->flags & QQ_THREAD_EVENTS) == 0 &&
		    w->pid == sample->sample_id.pid)
			return (NULL);
		if ((raw = raw_event_alloc()) == NULL)
			return (NULL);
		raw->type = RAW_WAKE_UP_NEW_TASK;
		raw->wake_up_new_task = *w;
		raw->pid = w->pid;
		raw->tid = w->tid;
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

	switch (ev->header.type) {
	case PERF_RECORD_FORK:
		/* Drop thread "forks" */
		if ((qq->flags & QQ_FORK_EVENTS) == 0)
			return (NULL);
		if ((qq->flags & QQ_THREAD_EVENTS) == 0 &&
		    ev->fork.pid == ev->fork.ppid)
			return (NULL);
		if ((raw = raw_event_alloc()) == NULL)
			return (NULL);
		raw->type = RAW_FORK;
		sid = &ev->fork.sample_id;
		/* We cheat FORK to be an event of the child, not the parent */
		raw->pid = raw->fork.child_pid = ev->fork.pid;
		raw->fork.parent_pid = ev->fork.ppid;
		break;
	case PERF_RECORD_EXIT:
		/* Drop thread "exits" */
		if ((qq->flags & QQ_THREAD_EVENTS) == 0 &&
		    ev->exit.pid != ev->exit.tid)
			return (NULL);
		if ((raw = raw_event_alloc()) == NULL)
			return (NULL);
		raw->type = RAW_EXIT;
		sid = &ev->exit.sample_id;
		break;
	case PERF_RECORD_SAMPLE:
		raw = perf_sample_to_raw(qq, &ev->sample);
		if (raw != NULL)
			sid = &ev->sample.sample_id;
		break;
	default:
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
	struct perf_event_header *evh;
	uint64_t data_head;
	int diff;
	ssize_t leftcont;	/* contiguous size left */

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
	int	 dfd, fd, i, r;
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

	for (i = 0; i < (int)nitems(paths); i++) {
		if ((dfd = open(paths[i], O_PATH)) == -1) {
			warn("open: %s", paths[i]);
			continue;
		}
		fd = openat(dfd, tail, flags);
		close(dfd);
		if (fd == -1) {
			warn("open: %s", tail);
			continue;
		}

		return (fd);
	}

	return (errno = ENOENT, -1);
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
	if (n == -1)
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

	quark_probe_data_body_offset = data_offset;

	return (data_offset);
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
		if (*p == '+') {
			const char *errstr;
			off = strtonum(p + 1, 0, UINT32_MAX, &errstr);
			if (errstr != NULL) {
				warnx("%s: bad +val %s: %s",
				    __func__, p, errstr);
				off = -1;
			}
		} else
			off = quark_btf_offset(p);
		if (off == -1 ||
		    asprintf(&kstr, "+%zd(%s)", off, last) == -1) {
			if (off == -1)
				warnx("%s: %s is unresolved\n", __func__, p);
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
	struct kprobe_arg *karg;
	char *p, *o, *a;
	int r;

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
	    PERF_SAMPLE_STREAM_ID	| /* We can likely get rid of this one */
	    PERF_SAMPLE_CPU		|
	    PERF_SAMPLE_RAW;

	/* attr->read_format = PERF_FORMAT_LOST; */
	/* attr->mmap2 */
	/* attr->comm_exec */
	attr->use_clockid = 1;
	attr->clockid = CLOCK_MONOTONIC_RAW;
	/* wakeup forcibly if ring buffer is at least 10% full */
	attr->watermark = 1;
	/* XXXXXX SHOULD WE DO THIS IN THE CHILD AS WELL?????? XXXXXXX */
	attr->wakeup_watermark = (PERF_MMAP_PAGES * getpagesize()) / 10;
	attr->disabled = 1;
}

static int
perf_open_group_leader(struct perf_group_leader *pgl, int cpu)
{
	int id;

	/* By putting EXEC on group leader we save one fd per cpu */
	if ((id = fetch_tracing_id("events/sched/sched_process_exec/id")) == -1)
		return (-1);
	perf_attr_init(&pgl->attr, id);
	pgl->attr.task = 1;			/* PERF_RECORD_{FORK,EXIT} */
	pgl->attr.sample_id_all = 1;		/* add sample_id to all types */
	pgl->fd = perf_event_open(&pgl->attr, -1, cpu, -1, 0);
	if (pgl->fd == -1)
		return (-1);
	if (perf_mmap_init(&pgl->mmap, pgl->fd) == -1) {
		close(pgl->fd);
		return (-1);
	}
	pgl->cpu = cpu;
	id_to_sample_kind[id] = EXEC_SAMPLE;

	return (0);
}

static int
perf_open_kprobe(struct kprobe_state *ks, int cpu, int group_fd)
{
	int	id;
	char	buf[MAXPATHLEN];

	if (snprintf(buf, sizeof(buf), "events/kprobes/%s/id", ks->k->name)
	    >= (int)sizeof(buf))
		return (errno = ENAMETOOLONG, -1);
	if ((id = fetch_tracing_id(buf)) == -1)
		return (-1);
	perf_attr_init(&ks->attr, id);
	ks->fd = perf_event_open(&ks->attr, -1, cpu, group_fd, 0);
	if (ks->fd == -1)
		return (-1);
	/* Output our records in the group_fd */
	if (ioctl(ks->fd, PERF_EVENT_IOC_SET_OUTPUT, group_fd) == -1) {
		close(ks->fd);
		ks->fd = -1;
		return (-1);
	}
	ks->cpu = cpu;
	ks->group_fd = group_fd;
	id_to_sample_kind[id] = ks->k->sample_kind;

	return (0);
}

static void
dump_sample(struct perf_record_sample *sample)
{
	int	id = sample_data_id(sample);

	switch (sample_kind_of_id(id)) {
	case EXEC_SAMPLE: {
		struct exec_sample *exec = sample_data_body(sample);
		struct qstr qstr;

		qstr_init(&qstr);
		if (qstr_copy_data_loc(&qstr, sample, &exec->filename) == -1)
			warnx("can't copy exec filename");
		printf("->exec (%d)\n\tfilename=%s\n", id, qstr.p);
		qstr_free(&qstr);
		break;
	}
	case WAKE_UP_NEW_TASK_SAMPLE: {
		struct wake_up_new_task_sample *w;
		printf("->wake_up_new_task (%d)\n\t", id);
		w = sample_data_body(sample);
		printf("pid=%d tid=%d uid=%d gid=%d suid=%d sgid=%d euid=%d egid=%d\n",
		    w->pid, w->tid, w->uid, w->gid, w->suid, w->sgid, w->euid, w->egid);
		printf("\tcap_inheritable=0x%llx cap_permitted=0x%llx cap_effective=0x%llx\n"
		    "\tcap_bset=0x%llx cap_ambient=0x%llx\n",
		    w->cap_inheritable, w->cap_permitted, w->cap_effective,
		    w->cap_bset, w->cap_ambient);
		break;
	}
	default:
		warnx("%s: unknown or invalid sample id=%d", __func__, id);
	}
}

static void
dump_event(struct perf_event *ev)
{
	struct perf_sample_id		*sid = NULL;
	struct perf_record_fork		*fork;
	struct perf_record_exit		*exit;
	struct perf_record_sample	*sample;

	switch (ev->header.type) {
	case PERF_RECORD_FORK:
		fork = &ev->fork;
		sid = &fork->sample_id;
		printf("->fork\n\tpid=%d ppid=%d tid=%d ptid=%d time=%llu\n",
		    fork->pid, fork->ppid, fork->tid, fork->ptid, fork->time);
		break;
	case PERF_RECORD_EXIT:
		exit = &ev->exit;
		sid = &exit->sample_id;
		printf("->exit\n\tpid=%d ppid=%d tid=%d ptid=%d time=%llu\n",
		    exit->pid, exit->ppid, exit->tid, exit->ptid, exit->time);
		break;
	case PERF_RECORD_SAMPLE:
		sample = &ev->sample;
		sid = &sample->sample_id;
		dump_sample(sample);
		break;

	default:
		printf("->Unhandled(type %d)\n", ev->header.type);
		break;
	}

	if (sid != NULL)
		printf("\ts.pid=%d s.tid=%d s.time=%llu (age=%llu)"
		    " s.stream_id=%llu s.cpu=%d\n",
		    sid->pid, sid->tid, sid->time, AGE(sid->time, now64()),
		    sid->stream_id, sid->cpu);

	fflush(stdout);
}

static void
xfprintf(FILE *f, const char *restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (vfprintf(f, fmt, ap) < 0)
		errx(1, "xfprintf");
	va_end(ap);
}

static void
write_node_attr(FILE *f, struct raw_event *raw, char *key)
{
	const char		*color;
	char			 label[4096];

	switch (raw->type) {
	case RAW_FORK:
		color = "lightgoldenrod";
		(void)snprintf(label, sizeof(label), "FORK %d",
		    raw->fork.child_pid);
		break;
	case RAW_EXIT:
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
		struct wake_up_new_task_sample *w = &raw->wake_up_new_task;
		color = "orange";
		if (snprintf(label, sizeof(label), "NEW_TASK %d",
		    w->pid) >= (int)sizeof(label))
			warnx("%s: snprintf", __func__);
		break;
	}
	default:
		color = "black";
		break;
	}
	xfprintf(f, "\"%s\" [label=\"%llu\\n%s\\npid %d\", fillcolor=%s];\n",
	    key, raw->time, label, raw->pid, color);
}

static void
write_graphviz(struct quark_queue *qq, FILE *by_time, FILE *by_pidtime)
{
	struct raw_event	*raw, *left, *right;
	FILE			*f;
	char			 key[256];

	f = by_time;

	xfprintf(f, "digraph {\n");
	xfprintf(f, "node [style=filled, color=black];\n");
	RB_FOREACH(raw, raw_event_by_time, &qq->raw_event_by_time) {
		snprintf(key, sizeof(key), "%llu", raw->time);
		write_node_attr(f, raw, key);
	}
	RB_FOREACH(raw, raw_event_by_time, &qq->raw_event_by_time) {
		left = RB_LEFT(raw, entry_by_time);
		right = RB_RIGHT(raw, entry_by_time);

		if (left != NULL)
			xfprintf(f, "%llu -> %llu;\n",
			    raw->time, left->time);
		if (right != NULL)
			xfprintf(f, "%llu -> %llu;\n",
			    raw->time, right->time);
	}
	xfprintf(f, "}\n");

	fflush(f);
	fclose(f);

	f = by_pidtime;

	xfprintf(f, "digraph {\n");
	xfprintf(f, "node [style=filled, color=black];\n");
	RB_FOREACH(raw, raw_event_by_pidtime, &qq->raw_event_by_pidtime) {
		snprintf(key, sizeof(key), "%d %llu",
		    raw->pid, raw->time);
		write_node_attr(f, raw, key);
	}
	RB_FOREACH(raw, raw_event_by_pidtime, &qq->raw_event_by_pidtime) {
		left = RB_LEFT(raw, entry_by_pidtime);
		right = RB_RIGHT(raw, entry_by_pidtime);

		if (left != NULL) {
			xfprintf(f, "\"%d %llu\" -> \"%d %llu\";\n",
			    raw->pid, raw->time,
			    left->pid, left->time);
		}
		if (right != NULL)
			xfprintf(f, "\"%d %llu\" -> \"%d %llu\";\n",
			    raw->pid, raw->time,
			    right->pid, right->time);
	}
	xfprintf(f, "}\n");

	fflush(f);
	fclose(f);
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
	qq->stats.insertions++;
}

static void
raw_event_remove(struct quark_queue *qq, struct raw_event *raw)
{
	RB_REMOVE(raw_event_by_time, &qq->raw_event_by_time, raw);
	RB_REMOVE(raw_event_by_pidtime, &qq->raw_event_by_pidtime, raw);
	qq->stats.removals++;
}

static int
block(struct perf_group_leaders *leaders)
{
	struct perf_group_leader	*pgl;
	struct pollfd			*fds;
	struct timespec			 ts;
	int				 i, nfds, r;

	nfds = 0;
	TAILQ_FOREACH(pgl, leaders, entry) {
		nfds++;
	}
	fds = calloc(sizeof(*fds), nfds);
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

static int
quark_queue_open(struct quark_queue *qq, int flags)
{
	int				 i;
	struct perf_group_leader	*pgl;
	struct kprobe			*k;
	struct kprobe_state		*ks;

	bzero(qq, sizeof(*qq));

	TAILQ_INIT(&qq->perf_group_leaders);
	TAILQ_INIT(&qq->kprobe_states);
	RB_INIT(&qq->raw_event_by_time);
	RB_INIT(&qq->raw_event_by_pidtime);
	qq->flags = flags;

	for (i = 0; i < get_nprocs_conf(); i++) {
		pgl = calloc(1, sizeof(*pgl));
		if (pgl == NULL)
			err(1, "calloc"); /* XXX TODO proper cleanup */
		if (perf_open_group_leader(pgl, i) == -1)
			errx(1, "perf_open_group_leader"); /* XXX TODO proper cleanup */
		TAILQ_INSERT_TAIL(&qq->perf_group_leaders, pgl, entry);
	}

	i = 0;
	while ((k = all_kprobes[i++]) != NULL) {
	TAILQ_FOREACH(pgl, &qq->perf_group_leaders, entry) {
		ks = calloc(1, sizeof(*ks));
		if (ks == NULL)
			err(1, "calloc"); /* XXX TODO proper cleanup */
		ks->k = k;
		if (perf_open_kprobe(ks, pgl->cpu, pgl->fd) == -1)
			errx(1, "perf_open_kprobe"); /* XXX TODO proper cleanup */
		TAILQ_INSERT_TAIL(&qq->kprobe_states, ks, entry);
	}}

	TAILQ_FOREACH(pgl, &qq->perf_group_leaders, entry) {
		/* XXX PERF_IOC_FLAG_GROUP see bugs */
		if (ioctl(pgl->fd, PERF_EVENT_IOC_RESET,
		    PERF_IOC_FLAG_GROUP) == -1)
			err(1, "ioctl PERF_EVENT_IOC_RESET:");
		if (ioctl(pgl->fd, PERF_EVENT_IOC_ENABLE,
		    PERF_IOC_FLAG_GROUP) == -1)
			err(1, "ioctl PERF_EVENT_IOC_ENABLE:");
	}

	return (0);
#undef O
}

static void
quark_queue_close(struct quark_queue *qq)
{
	struct perf_group_leader	*pgl;
	struct kprobe_state		*ks;
	struct raw_event		*raw, *aux;

	/* Stop and close the perf rings */
	while ((pgl = TAILQ_FIRST(&qq->perf_group_leaders)) != NULL) {
		/* XXX PERF_IOC_FLAG_GROUP see bugs */
		if (ioctl(pgl->fd, PERF_EVENT_IOC_DISABLE,
		    PERF_IOC_FLAG_GROUP) == -1)
			warnx("ioctl PERF_EVENT_IOC_DISABLE:");
		close(pgl->fd);
		if (munmap(pgl->mmap.metadata, pgl->mmap.mapped_size) != 0)
			warn("munmap");
		TAILQ_REMOVE(&qq->perf_group_leaders, pgl, entry);
		free(pgl);
	}
	/* Clean up all state allocated to kprobes */
	while ((ks = TAILQ_FIRST(&qq->kprobe_states)) != NULL) {
		close(ks->fd);
		TAILQ_REMOVE(&qq->kprobe_states, ks, entry);
		free(ks);
	}
	/* Clean up all allocated raw events */
	while ((raw = RB_ROOT(&qq->raw_event_by_time)) != NULL) {
		raw_event_remove(qq, raw);
		while ((aux = TAILQ_FIRST(&raw->agg_queue)) != NULL) {
			TAILQ_REMOVE(&raw->agg_queue, aux, agg_entry);
			free(aux);
		}

		raw_event_free(raw);
	}
	if (!RB_EMPTY(&qq->raw_event_by_pidtime))
		warnx("raw_event trees not empty");
}

static void
quark_queue_dump_stats(struct quark_queue *qq)
{
	struct quark_queue_stats *s = &qq->stats;
	printf("%8llu insertions %8llu removals %8llu aggregations %8llu non-aggregations\n",
	    s->insertions, s->removals, s->aggregations, s->non_aggregations);
}

static void
quark_queue_aggregate(struct quark_queue *qq, struct raw_event *min)
{
	struct raw_event	*next, *aux;
	int			 agg = 0;

	if (min->type != RAW_WAKE_UP_NEW_TASK) {
		qq->stats.non_aggregations++;
		return;
	}
	next = RB_NEXT(raw_event_by_pidtime, &qq->raw_event_by_pidtime,
	    min);

	if (next != NULL &&
	    next->pid == min->pid &&
	    next->type == RAW_EXEC) {
		aux = next;
		next = RB_NEXT(raw_event_by_pidtime,
		    &qq->raw_event_by_pidtime, next);
		raw_event_remove(qq, aux);
		TAILQ_INSERT_TAIL(&min->agg_queue, aux, agg_entry);
		agg++;
	} else
		return;
	if (next != NULL &&
	    next->pid == min->pid &&
	    next->type == RAW_EXIT) {
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

static int
quark_queue_process(struct quark_queue *qq)
{
	int			 nproc;
	struct raw_event	*min, *next, *aux;
	u64			 now;

	nproc = 0;
	now = now64();
	min = RB_MIN(raw_event_by_time, &qq->raw_event_by_time);
	while (min != NULL) {
		if (!raw_event_expired(min, now))
			break;

		quark_queue_aggregate(qq, min);

		raw_event_dump(min, 0);
		while ((aux = TAILQ_FIRST(&min->agg_queue)) != NULL) {
			TAILQ_REMOVE(&min->agg_queue, aux, agg_entry);
			raw_event_free(aux);
			nproc++;
		}

		next = RB_NEXT(raw_event_by_time, &qq->raw_event_by_time, min);
		raw_event_remove(qq, min);
		raw_event_free(min);
		nproc++;
		min = next;
	}

	return (nproc);
}

static int
quark_init(void)
{
	if (parse_probe_data_body_offset() == -1) {
		warnx("%s: can't parse host probe data offset\n",
		    __func__);
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

static int
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

/*
 * End of library
 */

static int gotsigint;

static void
sigint_handler(int sig)
{
	gotsigint = 1;
}

static void
priv_drop(void)
{
	struct passwd	*pw;

	/* getpwnam_r is too painful for a demo */
	if ((pw = getpwnam("nobody")) == NULL)
		err(1, "getpwnam");

	/* chroot */
	if (chroot("/var/empty") == -1)
		err(1, "chroot");
	if (chdir("/") == -1)
		err(1, "chdir");

	/* setproctitle would be here */

	/* become the weakling */
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		err(1, "error dropping privileges");
}

int
main(int argc, char *argv[])
{
	int				 ch, maxnodes, nodes, nproc;
	int				 dump_perf, qq_flags, ncpus;
	int				 empty_rings, credits, do_drop;
	struct perf_group_leader	*pgl;
	struct perf_event		*ev;
	struct raw_event		*raw;
	struct quark_queue		*qq;
	struct sigaction		 sigact;
	FILE				*graph_by_time, *graph_by_pidtime;

	maxnodes = -1;
	nodes = 0;
	qq_flags = dump_perf = do_drop = 0;

	while ((ch = getopt(argc, argv, "Dfm:pt")) != -1) {
		const char *errstr;

		switch (ch) {
		case 'D':
			do_drop = 1;
			break;
		case 'f':
			qq_flags |= QQ_FORK_EVENTS;
			break;
		case 'm':
			maxnodes = strtonum(optarg, 1, 2000000, &errstr);
			if (errstr != NULL)
				errx(1, "invalid maxnodes: %s", errstr);
			break;
		case 'p':
			dump_perf = 1;
			break;
		case 't':
			qq_flags |= QQ_THREAD_EVENTS;
			break;
		default:
			errx(1, "usage: TODO");
		}
	}

	bzero(&sigact, sizeof(sigact));
	sigact.sa_flags = SA_RESTART | SA_RESETHAND;
	sigact.sa_handler = &sigint_handler;
	if (sigaction(SIGINT, &sigact, NULL) == -1)
		err(1, "sigaction");

	if (quark_init() == -1)
		errx(1, "quark_init");
	if ((qq = calloc(1, sizeof(*qq))) == NULL)
		err(1, "calloc");
	if (quark_queue_open(qq, qq_flags) != 0)
		errx(1, "quark_queue_open");
	/* open graphviz files before priv_drop */
	graph_by_time = fopen("quark_by_time.dot", "w");
	if (graph_by_time == NULL)
		err(1, "fopen");
	graph_by_pidtime = fopen("quark_by_pidtime.dot", "w");
	if (graph_by_pidtime == NULL)
		err(1, "fopen");

	/* From now on we will be nobody */
	if (do_drop)
		priv_drop();

	ncpus = get_nprocs_conf();
	while (!gotsigint && (maxnodes == -1 || nodes < maxnodes)) {
		credits = 1000;
		empty_rings = 0;
		while (empty_rings < ncpus && credits > 0) {
		TAILQ_FOREACH(pgl, &qq->perf_group_leaders, entry) {
			ev = perf_mmap_read(&pgl->mmap);
			if (ev == NULL) {
				empty_rings++;
				continue;
			}
			empty_rings = 0;
			credits--;
			raw = perf_event_to_raw(qq, ev);
			if (raw != NULL) {
				if (dump_perf)
					dump_event(ev);
				/* Useful for debugging */
				/* raw->time = arc4random_uniform(100000); */
				raw_event_insert(qq, raw);
				nodes++;
			}
			perf_mmap_consume(&pgl->mmap);
		}}

		/* If maxnodes is set, we don't want to process, only collect */
		if (maxnodes == -1) {
			nproc = quark_queue_process(qq);
			if (nproc)
				printf("removed %d nodes\n", nproc);
		}

		/*
		 * Only block if we got here with credits left, otherwise we're
		 * trying to catch up with the kernel.
		 */
		if (credits > 0)
			block(&qq->perf_group_leaders);
	}

	RB_FOREACH(raw, raw_event_by_time, &qq->raw_event_by_time) {
		printf("%llu (age=%llu)\n", raw->time,
		    raw_event_age(raw, now64()));
	}

	write_graphviz(qq, graph_by_time, graph_by_pidtime);

	quark_queue_dump_stats(qq);
	quark_queue_close(qq);
	free(qq);
	if (!do_drop)
		quark_close();

	return (0);
}
