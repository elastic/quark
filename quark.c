#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

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
#define QUARK_QUEUE_MAXLENGTH	10000		/* XXX hardcoded for now XXX */
#define AGE(_ts, _now) 		((_ts) > (_now) ? 0 : (_now) - (_ts))
#define MAX_SAMPLE_IDS		4096		/* id_to_sample_kind map */

static int	open_tracing(int, const char *, ...) __attribute__((format(printf, 2, 3)));
static int	raw_event_by_time_cmp(struct raw_event *, struct raw_event *);
static int	raw_event_by_pidtime_cmp(struct raw_event *, struct raw_event *);

/* For debugging */
int	quark_verbose;

/* matches each sample event to a kind like EXEC_SAMPLE, FOO_SAMPLE */
u8	id_to_sample_kind[MAX_SAMPLE_IDS];

/*
 * This is the offset from the common area of a probe to the body. It is almost
 * always 8, but some older redhat kernels are different.
 */
ssize_t	quark_probe_data_body_offset;

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

void
raw_event_free(struct raw_event *raw)
{
	struct raw_event *aux;

	switch (raw->type) {
	case RAW_EXEC:
		qstr_free(&raw->exec.filename);
		break;
	case RAW_WAKE_UP_NEW_TASK:
	case RAW_EXIT_THREAD:
		free(raw->task.cwd);
		break;
	case RAW_EXEC_CONNECTOR:
		qstr_free(&raw->exec_connector.args);
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

void
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
		printf("\tstart_time=%llu start_boottime=%llu",
		    w->start_time, w->start_boottime);
		if (raw->type == RAW_WAKE_UP_NEW_TASK)
			printf(" norm_start=%llu", raw->time);
		printf("\n");
		printf("\tcap_inheritable=0x%llx cap_permitted=0x%llx cap_effective=0x%llx\n"
		    "\tcap_bset=0x%llx cap_ambient=0x%llx\n",
		    w->cap_inheritable, w->cap_permitted, w->cap_effective,
		    w->cap_bset, w->cap_ambient);
		if (raw->type == RAW_WAKE_UP_NEW_TASK) {
			printf("\tworking_directory=%s\n", w->cwd);
			printf("\tppid=%d\n", w->ppid);
		} else if (raw->type == RAW_EXIT_THREAD)
			printf("\texit_code=%d norm_end=%llu\n", w->exit_code, raw->time);
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

static char *
build_path(struct path_ctx *ctx)
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
			return (errno = ENAMETOOLONG, NULL);
		while (ppwd != pwd)
			*--p = *--ppwd;
		*--p = '/';
	}
	if (*p == 0)
		*--p = '/';

	/* XXX double copy XXX */
	return (strdup(p));
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
			raw->task.cwd = build_path(&pctx);
			raw->task.exit_code = -1;
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
		}
		raw->task.cap_inheritable = w->cap_inheritable;
		raw->task.cap_permitted = w->cap_permitted;
		raw->task.cap_effective = w->cap_effective;
		raw->task.cap_bset = w->cap_bset;
		raw->task.cap_ambient = w->cap_ambient;
		raw->task.start_time = w->start_time;
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
		exec->argc = i;
		if (qstr_memcpy(&exec->args, start, p - start) == -1)
			warnx("can't copy args");
		if (p == end)
			exec->args.p[p - start - 1] = 0;
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

static int
perf_open_group_leader(struct perf_group_leader *pgl, int cpu)
{
	int id;

	/* By putting EXEC on group leader we save one fd per cpu */
	if ((id = fetch_tracing_id("events/sched/sched_process_exec/id")) == -1)
		return (-1);
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

#define P(_f, ...)				\
	if (fprintf(_f, __VA_ARGS__) < 0)	\
		return (-1);
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

	bzero(qq, sizeof(*qq));

	TAILQ_INIT(&qq->perf_group_leaders);
	qq->num_perf_group_leaders = 0;
	TAILQ_INIT(&qq->kprobe_states);
	RB_INIT(&qq->raw_event_by_time);
	RB_INIT(&qq->raw_event_by_pidtime);
	qq->flags = flags;
	qq->length = 0;
	qq->max_length = QUARK_QUEUE_MAXLENGTH;

	for (i = 0; i < get_nprocs_conf(); i++) {
		pgl = calloc(1, sizeof(*pgl));
		if (pgl == NULL)
			err(1, "calloc"); /* XXX TODO proper cleanup */
		if (perf_open_group_leader(pgl, i) == -1)
			errx(1, "perf_open_group_leader"); /* XXX TODO proper cleanup */
		TAILQ_INSERT_TAIL(&qq->perf_group_leaders, pgl, entry);
		qq->num_perf_group_leaders++;
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
}

void
quark_queue_close(struct quark_queue *qq)
{
	struct perf_group_leader	*pgl;
	struct kprobe_state		*ks;
	struct raw_event		*raw;

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
		raw_event_free(raw);
	}
	if (!RB_EMPTY(&qq->raw_event_by_pidtime))
		warnx("raw_event trees not empty");
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
	while (next != NULL) {
		/* Different pids can't merge */
		if (next->pid != min->pid)
			break;
		/* We only aggregate these into fork for now */
		if (next->type != RAW_EXEC &&
		    next->type != RAW_EXIT_THREAD &&
		    next->type != RAW_COMM &&
		    next->type != RAW_EXEC_CONNECTOR)
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

struct raw_event *
quark_queue_pop(struct quark_queue *qq)
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
