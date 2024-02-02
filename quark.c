#include <bsd/stdlib.h>
#include <bsd/string.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <strings.h>

#include "quark.h"

#define PERF_MMAP_PAGES 16	/* Must be power of 2 */

static int
raw_event_cmp(struct raw_event *a, struct raw_event *b)
{
	if (a->sample_id.time < b->sample_id.time)
		return (-1);
	else
		return (a->sample_id.time > b->sample_id.time);
}

RB_HEAD(raw_event_tree, raw_event) raw_event_tree = RB_INITIALIZER(&raw_event_tree);
RB_PROTOTYPE(raw_event_tree, raw_event, entry, raw_event_cmp);
RB_GENERATE(raw_event_tree, raw_event, entry, raw_event_cmp);

/*
 * Copies out the string pointed to by data size, if retval is >= than dst_size,
 * it means we truncated. May return -1 on bad values.
 */
static ssize_t
copy_data_loc(void *dst, ssize_t dst_size, struct perf_record_sample *sample,
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
		break;
	case PERF_RECORD_EXIT:
		raw->type = RAW_EXIT;
		sid = &ev->exit.sample_id;
		break;
	case PERF_RECORD_SAMPLE:
		/* XXX CHEAT FOR NOW XXX */
		raw->type = RAW_EXEC;
		sid = &ev->sample.sample_id;
		n = copy_data_loc(raw->exec.filename, sizeof(raw->exec.filename),
		    &ev->sample, 8);
		if (n == -1)
			warnx("can't copy exec filename");
		else if (n >= (ssize_t)sizeof(raw->exec.filename))
			warnx("exec filename truncated");
		break;
	default:
		errx(1, "perf_to_raw: unknown event type %d\n", ev->header.type);
	}

	if (sid != NULL)
		raw->sample_id = *sid;

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
		/* XXX hardcorded offset XXX */
		n = copy_data_loc(buf, sizeof(buf), &ev->sample, 8);
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
		printf("\ts.pid=%d s.tid=%d s.time=%llu s.stream_id=%llu s.cpu=%d\n",
		    sid->pid, sid->tid, sid->time, sid->stream_id, sid->cpu);

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
write_graphviz(void)
{
	struct raw_event	*raw, *left, *right;
	FILE			*f;
	const char		*color;
	char			 label[4096];

	f = fopen("quark.dot", "w");
	if (f == NULL)
		err(1, "fopen");
	if (fprintf(f, "digraph {\n") < 0)
		errx(1, "fprintf");
	if (fprintf(f, "node [style=filled, color=black];") < 0)
		errx(1, "fprintf");

	RB_FOREACH(raw, raw_event_tree, &raw_event_tree) {
		switch (raw->type) {
		case RAW_FORK:
			color = "lightgoldenrod";
			(void)strlcpy(label, "FORK", sizeof(label));
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
		if (fprintf(f, "%llu [label=\"%llu\\n%s\\npid %d\", fillcolor=%s];\n",
		    raw->sample_id.time, raw->sample_id.time, label,
		    raw->sample_id.pid, color) == -1)
			errx(1, "fprintf");
	}

	RB_FOREACH(raw, raw_event_tree, &raw_event_tree) {
		left = RB_LEFT(raw, entry);
		right = RB_RIGHT(raw, entry);

		if (left != NULL) {
			if (fprintf(f, "%llu -> %llu;\n",
			    raw->sample_id.time, left->sample_id.time) == -1)
				errx(1, "fprintf");

		}
		if (right != NULL) {
			if (fprintf(f, "%llu -> %llu;\n",
			    raw->sample_id.time, right->sample_id.time) == -1)
				errx(1, "fprintf");

		}
	}
	if (fprintf(f, "}\n") < 0)
		errx(1, "fprintf");

	fflush(f);
	fclose(f);
}

/*
 * Insert without a colision, cheat on the timestamp in case we do. NOTE: since
 * we bump "time" here, we shouldn't copy "time" before it sits in the tree.
 */
static void
raw_event_tree_insert_nocol(struct raw_event *raw)
{
	struct raw_event	*col;
	int			 attempts = 10;

	do {
		col = RB_INSERT(raw_event_tree, &raw_event_tree, raw);
		if (unlikely(col != NULL))
			warnx("raw_event_tree collision");
		/*
		 * We managed to get a collision on the TSC, this happens!
		 * We just bump time by one until we can insert it.
		 */
		raw->sample_id.time++;
	} while (unlikely(col != NULL && --attempts > 0));

	if (col != NULL)
		err(1, "we got consecutive collisions, this is a bug");
}

int
main(int argc, char *argv[])
{
	int				 i;
	struct perf_group_leader	*pgl;
	struct perf_event		*ev;
	struct raw_event		*raw;
	int				 nodes = 0;
	TAILQ_HEAD(perf_group_leaders, perf_group_leader) leaders =
	    TAILQ_HEAD_INITIALIZER(leaders);

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
				/* Useful for debugging */
				/* raw->time = arc4random_uniform(100000); */
				raw_event_tree_insert_nocol(raw);
				nodes++;
			} else
				warnx("can't convert perf to raw");
			perf_mmap_consume(&pgl->mmap);
		}
	}

	RB_FOREACH(raw, raw_event_tree, &raw_event_tree) {
		printf("%llu\n", raw->sample_id.time);
	}

	write_graphviz();

	return (0);
}
