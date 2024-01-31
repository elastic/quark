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
#include <strings.h>
#include <unistd.h>

#include "freebsd_queue.h"

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
};

struct perf_group_leader {
	TAILQ_ENTRY(perf_group_leader)	 entry;
	int				 fd;
	int				 cpu;
	struct perf_event_attr		 attr;
	struct perf_mmap		 mmap;
};

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

static ssize_t
perf_mmap_read(struct perf_mmap *mm, void *buf, size_t buflen)
{
	struct perf_event_mmap_page *meta;
	struct perf_event_header *evh;
	uint64_t data_head;
	int diff;
	ssize_t copyleft, leftcont, thiscopy, off;
	uint8_t *pbuf;

	meta = mm->metadata;
	data_head = perf_mmap_load_head(meta);
	diff = data_head - meta->data_tail;
	pbuf = buf;

	evh = (struct perf_event_header *)
	    (mm->data_start + (meta->data_tail & mm->data_mask));

	if (diff < (int)sizeof(*evh) || diff < evh->size) {
		errno = EAGAIN;
		return (-1);
	}

	/* XXX just for now XXX */
	if (evh->size > buflen) {
		errno = EMSGSIZE;
		return (-1);
	}
	copyleft = evh->size;
	/* printf("evh->size=%d data_head=%lu data_mask=0x%lx evh=%p data_start=%p\n", */
	/*     evh->size, data_head, mm->data_mask, evh, mm->data_start); */
	off = 0;
	while (copyleft) {
		/* How much contiguous space there is left */
		leftcont = mm->data_mask + 1 - ((meta->data_tail + off) & mm->data_mask);
		/* How much this memcpy will copy, so it doesn't wrap */
		thiscopy = min(leftcont, copyleft);
		/* Do it */
		memcpy(pbuf, evh + off, thiscopy);
		off += thiscopy;
		pbuf += thiscopy;
		copyleft -= thiscopy;
	}

	/* "Tell" the kernel there is more space left */
	perf_mmap_update_tail(meta, meta->data_tail + off);

	return (off);
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

int
main(int argc, char *argv[])
{
	int				 i;
	struct perf_group_leader	*pgl;
	TAILQ_HEAD(perf_group_leaders, perf_group_leader) leaders =
	    TAILQ_HEAD_INITIALIZER(leaders);
	char buf[8192];
	struct my_perf_event *event = (struct my_perf_event *)buf;

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

	for (;;) {
		ssize_t n;

		TAILQ_FOREACH(pgl, &leaders, entry) {
			/* printf("cpu%2d head %llu tail %llu\n", */
			/*     pgl->cpu, pgl->mmap.metadata->data_head, */
			/*     pgl->mmap.metadata->data_tail); */
			n = perf_mmap_read(&pgl->mmap, buf, sizeof(buf));
			if (n == -1) {
				/* Nothing to be read */
				if (errno == EAGAIN)
					continue;
				/* Ooopsy */
				err(1, "perf_mmap_read");
			}
			dump_event(event);
			/* printf("read %zd bytes (type=%d, misc=%d, size=%d)\n", */
			/*     n, evh->type, evh->misc, evh->size); */
			/* printf("sizeof(evh) = %zd\n", sizeof(*evh)); */
		}
		sleep(1);
	}

	return (0);
}
