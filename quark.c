#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
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

static void xfprintf(FILE *, const char *, ...) __attribute__((format(printf, 2, 3)));

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

/*
 * Raw Event Tree by time, where RB_MIN() is the oldest element in the tree, no
 * clustering of pids so we can easily get the oldest event.
 */
RB_HEAD(raw_event_by_time, raw_event) raw_event_by_time =
    RB_INITIALIZER(&raw_event_by_time);
RB_PROTOTYPE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);
RB_GENERATE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);

/*
 * Raw Event Tree by pid and time, this creates clusters of the same pid which
 * are then organized by time, this is used in assembly and aggregation, if we
 * used the 'by_time' tree, we would have to traverse the full tree in case of a
 * miss.
 */
/* XXX this should be by tid, but we're not there yet XXX */
RB_HEAD(raw_event_by_pidtime, raw_event) raw_event_by_pidtime =
    RB_INITIALIZER(&raw_event_by_pidtime);
RB_PROTOTYPE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);
RB_GENERATE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);

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

/*
 * Copies out the string pointed to by data size, if retval is >= than dst_size,
 * it means we truncated. May return -1 on bad values.
 */
static ssize_t
strlcpy_data_loc(void *dst, ssize_t dst_size, struct perf_record_sample *sample,
    size_t data_off)
{
	struct perf_data_loc	*data_loc;
	ssize_t			 n;
	char			*p = dst;

	data_loc = (struct perf_data_loc *)(sample->data + data_off);
	n = min(dst_size, data_loc->size);
	if (n <= 0)
		return (-1);
	memcpy(p, sample->data + data_loc->offset, n);
	/* never trust the kernel */
	p[n - 1] = 0;

	return (n - 1);
}

static struct raw_event *
perf_to_raw(struct perf_event *ev)
{
	struct raw_event		*raw;
	struct perf_sample_id		*sid = NULL;
	ssize_t				 n;

	if ((raw = calloc(1, sizeof(*raw))) == NULL)
		return (NULL);

	switch (ev->header.type) {
	case PERF_RECORD_FORK:
		raw->type = RAW_FORK;
		sid = &ev->fork.sample_id;
		/* We cheat FORK to be an event of the child, not the parent */
		raw->pid = raw->fork.child_pid = ev->fork.pid;
		raw->fork.parent_pid = ev->fork.ppid;
		break;
	case PERF_RECORD_EXIT:
		raw->type = RAW_EXIT;
		sid = &ev->exit.sample_id;
		break;
	case PERF_RECORD_SAMPLE:
		/* XXX CHEAT FOR NOW XXX */
		raw->type = RAW_EXEC;
		sid = &ev->sample.sample_id;
		n = strlcpy_data_loc(raw->exec.filename, sizeof(raw->exec.filename),
		    &ev->sample, 8);
		if (n == -1)
			warnx("can't copy exec filename");
		else if (n >= (ssize_t)sizeof(raw->exec.filename))
			warnx("exec filename truncated");
		break;
	default:
		errx(1, "perf_to_raw: unknown event type %d\n", ev->header.type);
	}

	if (sid != NULL) {
		/* FORK overloads pid and tid */
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
	mm->data_mask = (PERF_MMAP_PAGES * getpagesize()) - 1;
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
	ssize_t leftcont, thiscopy, off;

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
	leftcont = mm->data_mask + 1 - (mm->data_tmp_tail & mm->data_mask);
	/* Everything fits without wrapping */
	if (likely(evh->size <= leftcont)) {
		mm->data_tmp_tail += evh->size;
		return ((struct perf_event *)evh);
	}

	/* Slow path, we have to copy the event out in a linear buffer */
	for (off = 0; evh->size - off != 0; off += thiscopy) {
		/* Calculate next contiguous area, must fit */
		leftcont = mm->data_mask + 1 -
		    ((mm->data_tmp_tail + off) & mm->data_mask);
		/* How much this memcpy will copy, so it doesn't wrap */
		thiscopy = min(leftcont, evh->size - off);
		/* Do it */
		memcpy(mm->wrapped_event_buf + off, evh + off, thiscopy);
	}
	/* Record where our future tail will be on release */
	mm->data_tmp_tail += evh->size;

	return ((struct perf_event *)evh);
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
fetch_tracing_id(const char *tail)
{
	int i;
	char path[MAXPATHLEN];
	char *epath[] = {
		"/sys/kernel/tracing/events",
		"/sys/kernel/debug/tracing/events"
	};

	for (i = 0; i < (int)nitems(epath); i++) {
		int id, fd;
		ssize_t n;
		char idbuf[16];
		const char *errstr;

		if (snprintf(path, sizeof(path),
		    "%s/%s/id", epath[i], tail) >= (int)sizeof(path)) {
			warnx("sptrinf");
			continue;
		}
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			warn("open: %s", path);
			continue;
		}
		n = read(fd, idbuf, sizeof(idbuf));
		if (n == -1) {/* XXX EINTR */
			close(fd);
			warn("read");
			continue;
		} else if (n == 0) {
			warn("read unexpected EOF");
			close(fd);
			continue;
		}
		close(fd);
		idbuf[n - 1] = 0;
		id = strtonum(idbuf, 0, INT_MAX, &errstr);
		if (errstr != NULL) {
			warnx("strtonum");
			continue;
		}

		return (id);
	}

	return (-1);
}

static int
perf_open_group_leader(struct perf_group_leader *pgl, int cpu)
{
	int			 id;
	struct perf_event_attr	*attr = &pgl->attr;

	bzero(pgl, sizeof(*pgl));

	attr->type = PERF_TYPE_TRACEPOINT;
	attr->size = sizeof(*attr);
	if ((id = fetch_tracing_id("sched/sched_process_exec")) == -1)
		return (-1);
	attr->config = id;
	/* attr->config = PERF_COUNT_SW_DUMMY; */
	attr->sample_period = 1;	/* we want all events */
	attr->sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU
	    | PERF_SAMPLE_RAW | PERF_SAMPLE_STREAM_ID; /* NOTE: why stream? */

	/* attr->read_format = PERF_FORMAT_LOST; */
	/* attr->mmap2 */
	/* attr->comm_exec */
	/* attr->sample_id_all */
	attr->use_clockid = 1;
	attr->clockid = CLOCK_MONOTONIC_RAW;
	attr->watermark = 0;	/* use number of samples, not bytes */
	attr->wakeup_events = 1;	/* XXX for testing */
	attr->task = 1;		/* get fork/exec, getting the same from two
				 * different things */
	attr->sample_id_all = 1;	/* affects non RECORD samples */
	attr->disabled = 1;

	pgl->fd = perf_event_open(attr, -1, cpu, -1, 0);
	if (pgl->fd == -1)
		return (-1);
	pgl->cpu = cpu;
	if (perf_mmap_init(&pgl->mmap, pgl->fd) == -1) {
		close(pgl->fd);
		return (-1);
	}

	return (0);
}

static void
dump_event(struct perf_event *ev)
{
	struct perf_sample_id		*sid = NULL;
	struct perf_record_fork		*fork;
	struct perf_record_exit		*exit;
	struct perf_record_sample	*sample;
	char				 buf[4096];
	ssize_t				 n;

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
		/* XXX hardcoded offset XXX */
		n = strlcpy_data_loc(buf, sizeof(buf), &ev->sample, 8);
		if (n == -1)
			warnx("can't copy exec filename");
		else if (n >= (ssize_t)sizeof(buf))
			warnx("exec filename truncated");
		printf("->exec\n\tfilename=%s\n", buf);
		break;

	default:
		printf("->Unhandled(type %d)\n", ev->header.type);
		break;
	}

	if (sid != NULL)
		printf("\ts.pid=%d s.tid=%d s.time=%llu (age=(%llu)) s.stream_id=%llu s.cpu=%d\n",
		    sid->pid, sid->tid, sid->time, AGE(sid->time, now64()),
		    sid->stream_id, sid->cpu);

	fflush(stdout);
}
#if 0
static const char *
type_to_str(int type)
{
	switch (type) {
	case PERF_RECORD_FORK:
		return "PERF_RECORD_FORK";
	case PERF_RECORD_EXIT:
		return "PERF_RECORD_EXIT";
	case PERF_RECORD_SAMPLE:
		return "PERF_RECORD_SAMPLE";
	}

	return "Unknown";
}
#endif

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
		    raw->exec.filename) >= (int)sizeof(label))
			warnx("%s: exec filename truncated", __func__);
		break;
	default:
		color = "black";
		break;
	}
	xfprintf(f, "\"%s\" [label=\"%llu\\n%s\\npid %d\", fillcolor=%s];\n",
	    key, raw->time, label, raw->pid, color);
}

static void
write_graphviz(void)
{
	struct raw_event	*raw, *left, *right;
	FILE			*f;
	char			 key[256];

	f = fopen("quark_by_time.dot", "w");
	if (f == NULL)
		err(1, "fopen");

	xfprintf(f, "digraph {\n");
	xfprintf(f, "node [style=filled, color=black];\n");
	RB_FOREACH(raw, raw_event_by_time, &raw_event_by_time) {
		snprintf(key, sizeof(key), "%llu", raw->time);
		write_node_attr(f, raw, key);
	}
	RB_FOREACH(raw, raw_event_by_time, &raw_event_by_time) {
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

	f = fopen("quark_by_pidtime.dot", "w");
	if (f == NULL)
		err(1, "fopen");

	xfprintf(f, "digraph {\n");
	xfprintf(f, "node [style=filled, color=black];\n");
	RB_FOREACH(raw, raw_event_by_pidtime, &raw_event_by_pidtime) {
		snprintf(key, sizeof(key), "%d %llu",
		    raw->pid, raw->time);
		write_node_attr(f, raw, key);
	}
	RB_FOREACH(raw, raw_event_by_pidtime, &raw_event_by_pidtime) {
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
raw_event_insert(struct raw_event *raw)
{
	struct raw_event	*col;
	int			 attempts = 10;

	/*
	 * Link it first by time
	 */
	do {
		col = RB_INSERT(raw_event_by_time, &raw_event_by_time, raw);
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
	col = RB_INSERT(raw_event_by_pidtime, &raw_event_by_pidtime, raw);
	if (unlikely(col != NULL))
		err(1, "collision on pidtime tree, this is a bug");
}

static void
raw_event_remove(struct raw_event *raw)
{
	RB_REMOVE(raw_event_by_time, &raw_event_by_time, raw);
	RB_REMOVE(raw_event_by_pidtime, &raw_event_by_pidtime, raw);
}

static int
raw_process(void)
{
	struct raw_event	*min, *next;	/* XXX todo cache min XXX */
	u64			 now, nproc;

	now = now64();
	nproc = 0;
	RB_FOREACH_SAFE(min, raw_event_by_time, &raw_event_by_time, next) {
		if (!raw_event_expired(min, now))
			break;
		raw_event_remove(min);
		free(min);
		nproc++;
	}

	return (nproc);
}

int
main(int argc, char *argv[])
{
	int				 ch, i, maxnodes, nodes, nproc;
	struct perf_group_leader	*pgl;
	struct perf_event		*ev;
	struct raw_event		*raw;
	TAILQ_HEAD(perf_group_leaders, perf_group_leader) leaders =
	    TAILQ_HEAD_INITIALIZER(leaders);

	maxnodes = -1;
	nodes = 0;
	while ((ch = getopt(argc, argv, "m:")) != -1) {
		const char *errstr;

		switch (ch) {
		case 'm':
			maxnodes = strtonum(optarg, 1, 2000000, &errstr);
			if (errstr != NULL)
				errx(1, "invalid maxnodes: %s", errstr);
			break;
		default:
			errx(1, "usage: TODO");
		}
	}

	printf("using %d bytes for each ring\n", PERF_MMAP_PAGES * getpagesize());

	for (i = 0; i < get_nprocs_conf(); i++) {
		pgl = calloc(1, sizeof(*pgl));
		if (pgl == NULL)
			err(1, "calloc");
		if (perf_open_group_leader(pgl, i) == -1)
			errx(1, "perf_open_group_leader");
		TAILQ_INSERT_TAIL(&leaders, pgl, entry);
	}

	TAILQ_FOREACH(pgl, &leaders, entry) {
		/* XXX PERF_IOC_FLAG_GROUP see bugs */
		if (ioctl(pgl->fd, PERF_EVENT_IOC_RESET,
		    PERF_IOC_FLAG_GROUP) == -1)
			err(1, "ioctl PERF_EVENT_IOC_RESET:");
		if (ioctl(pgl->fd, PERF_EVENT_IOC_ENABLE,
		    PERF_IOC_FLAG_GROUP) == -1)
			err(1, "ioctl PERF_EVENT_IOC_ENABLE:");
	}

	while (maxnodes == -1 || nodes < maxnodes) {
		TAILQ_FOREACH(pgl, &leaders, entry) {
			/* printf("cpu%2d head %llu tail %llu\n", */
			/*     pgl->cpu, pgl->mmap.metadata->data_head, */
			/*     pgl->mmap.metadata->data_tail); */
			ev = perf_mmap_read(&pgl->mmap);
			if (ev == NULL)
				continue;
			dump_event(ev);
			raw = perf_to_raw(ev);
			if (raw != NULL) {
				/* Useful for debugging */
				/* raw->time = arc4random_uniform(100000); */
				raw_event_insert(raw);
				nodes++;
			} else
				warnx("can't convert perf to raw");
			perf_mmap_consume(&pgl->mmap);
		}

		/* If maxnodes is set, we don't want to process, only collect */
		if (maxnodes == -1) {
			nproc = raw_process();
			if (nproc)
				printf("removed %d nodes\n", nproc);
		}
	}

	RB_FOREACH(raw, raw_event_by_time, &raw_event_by_time) {
		printf("%llu (age=%llu)\n", raw->time,
		    raw_event_age(raw, now64()));
	}

	write_graphviz();

	return (0);
}
