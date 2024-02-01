#define _GNU_SOURCE

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

#include <bsd/stdlib.h>
#include <bsd/string.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <unistd.h>

#include "freebsd_queue.h"
typedef uintptr_t __uintptr_t;
#include "freebsd_tree.h"
/* #include "openbsd_tree.h" */

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif	/* likely */

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif	/* unlikely */

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif	/* nitems */

#ifndef min
#define min(_a, _b)	((_a) < (_b) ? (_a) : (_b))
#endif	/* min */

#define PERF_MMAP_PAGES 16	/* Must be power of 2 */

struct my_perf_sample_id {
	__u32 pid;
	__u32 tid;
	__u64 time;
	__u64 stream_id;
	__u32 cpu;
	__u32 cpu_unused;
};

struct my_perf_record_fork {
	struct perf_event_header	header;
	__u32				pid;
	__u32				ppid;
	__u32				tid;
	__u32				ptid;
	__u64				time;
	struct my_perf_sample_id	sample_id;
};

struct my_perf_record_exit {
	struct perf_event_header	header;
	__u32				pid;
	__u32				ppid;
	__u32				tid;
	__u32				ptid;
	__u64				time;
	struct my_perf_sample_id	sample_id;
};

struct data_loc {
	__u16	offset;
	__u16	size;
};

struct my_perf_record_sample {
	struct perf_event_header	header;
	struct my_perf_sample_id	sample_id;
	__u32				size;
	char				data[];
};

struct my_perf_event {
	union {
		struct perf_event_header	header;
		struct my_perf_record_fork	fork;
		struct my_perf_record_exit	exit;
		struct my_perf_record_sample	sample;
	};
};

struct perf_mmap {
	struct perf_event_mmap_page	*metadata;
	size_t				 mapped_size;
	size_t				 data_mask;
	uint8_t				*data_start;
	__u64				 data_tmp_tail;
	__u8				 wrapped_event_buf[4096] __aligned(8);
};

struct perf_group_leader {
	TAILQ_ENTRY(perf_group_leader)	 entry;
	int				 fd;
	int				 cpu;
	struct perf_event_attr		 attr;
	struct perf_mmap		 mmap;
};

struct raw_event {
	RB_ENTRY(raw_event)	entry;
	__u64			time;
	int			type;
	__u64			pid;
};

static int
raw_event_cmp(struct raw_event *a, struct raw_event *b)
{
	if (a->time < b->time)
		return (-1);
	else if (a->time > b->time)
		return (1);
	else
		return (0);
}

static struct raw_event *
perf_to_raw(struct my_perf_event *ev)
{
	struct raw_event *raw;

	if ((raw = calloc(1, sizeof(*raw))) == NULL)
		return (NULL);

	raw->type = ev->header.type;
	switch (raw->type) {
	case PERF_RECORD_FORK:
		raw->pid = ev->fork.sample_id.pid;
		raw->time = ev->fork.sample_id.time;
		break;
	case PERF_RECORD_EXIT:
		raw->pid = ev->exit.sample_id.pid;
		raw->time = ev->exit.sample_id.time;
		break;
	case PERF_RECORD_SAMPLE:
		raw->pid = ev->sample.sample_id.pid;
		raw->time = ev->sample.sample_id.time;
		break;
	default:
		errx(1, "perf_to_raw: unknown event type");
	}

	return (raw);
}

RB_HEAD(raw_event_tree, raw_event) raw_event_tree = RB_INITIALIZER(&raw_event_tree);
RB_PROTOTYPE(raw_event_tree, raw_event, entry, raw_event_cmp);
RB_GENERATE(raw_event_tree, raw_event, entry, raw_event_cmp);

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
	printf("metadata=%p data_start=%p\n", mm->metadata, mm->data_start);

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

static struct my_perf_event *
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
		return ((struct my_perf_event *)evh);
	}
	errx(1, "TODO");
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

	return ((struct my_perf_event *)evh);
}

static inline void
perf_mmap_consume_event(struct perf_mmap *mmap)
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
	/* attr->use_clockid !!!!!! */
	attr->watermark = 0;	/* use number of samples, not bytes */
	attr->wakeup_events = 1;	/* XXX for testing */
	/* attr->clockid = ; !!!!!! */
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
dump_event(struct my_perf_event *ev)
{
	struct my_perf_sample_id	*sid = NULL;
	struct my_perf_record_fork	*fork;
	struct my_perf_record_exit	*exit;
	struct my_perf_record_sample	*sample;
	struct data_loc			*data_loc;
	char				 buf[4096];

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
		/* XXX hardcorded offset XXX */
		data_loc = (struct data_loc *)(sample->data + 8);
		/* XXX ignoring data_loc.size XXX */
		printf("->exec\n\t");
		if (data_loc->size > sizeof(buf)) {
			warnx("data_loc too big %d vs %zd\n",
			    data_loc->size, sizeof(buf));
			break;
		}
		memcpy(buf, sample->data + data_loc->offset, data_loc->size);
		buf[data_loc->size - 1] = 0;
		/* if (strlcpy(buf, sample->data + data_loc.offset, sizeof(buf)) >= */
		/*     sizeof(buf)) */
		/* 	warnx("filename truncated"); */
		printf("filename=%s\n", buf);
		break;

	default:
		printf("->Unhandled(type %d)\n", ev->header.type);
		break;
	}

	if (sid != NULL)
		printf("\ts.pid=%d s.tid=%d s.time=%llu s.stream_id=%llu s.cpu=%d\n",
		    sid->pid, sid->tid, sid->time, sid->stream_id, sid->cpu);

	fflush(stdout);
}

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

int
main(int argc, char *argv[])
{
	int				 i;
	struct perf_group_leader	*pgl;
	TAILQ_HEAD(perf_group_leaders, perf_group_leader) leaders =
	    TAILQ_HEAD_INITIALIZER(leaders);
	struct my_perf_event *ev;
	struct raw_event *raw;
	int nodes = 0;

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

	while (nodes < 100) {
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
				/* XXX CHEAT XXX */
				/* raw->time = arc4random_uniform(100000); */
				/* printf("time=%llu\n", raw->time); */
				if (RB_INSERT(raw_event_tree, &raw_event_tree, raw) != NULL)
					errx(1, "tree collission");
				nodes++;
			} else
				warnx("can't convert perf to raw");
			perf_mmap_consume_event(&pgl->mmap);
		}
	}

	RB_FOREACH(raw, raw_event_tree, &raw_event_tree) {
		printf("(%llu, %s, %llu) ", raw->time, type_to_str(raw->type), raw->pid);
	}

	printf("\n");


	return (0);
}
