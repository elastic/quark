#define _GNU_SOURCE

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

#include <bsd/stdlib.h>

#include <err.h>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))

static int
perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
    int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}


static int
fetch_tracing_id(const char *tail)
{
	int	i;
	char	path[MAXPATHLEN];
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
open_perf(int cpu)
{
	struct perf_event_attr attr;
	int id;

	bzero(&attr, sizeof(attr));

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(attr);
	if ((id = fetch_tracing_id("sched/sched_process_fork")) == -1)
		errx(1, "can't fetch id for sched_process_fork");
	attr.config = id;
	attr.sample_period = 1;	/* we want all events */
	attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU
	    | PERF_SAMPLE_RAW | PERF_SAMPLE_STREAM_ID; /* NOTE: why stream? */

	/* attr.read_format = PERF_FORMAT_LOST; */
	/* attr.mmap2 */
	/* attr.comm_exec */
	/* attr.sample_id_all */
	/* attr.use_clockid !!!!!! */
	attr.watermark = 0;	/* use number of samples, not bytes */
	attr.wakeup_events = 1;	/* XXX for testing */
	/* attr.clockid = ; !!!!!! */
	attr.task = 1;		/* get fork/exec, duplicates the tracepoint */
	attr.sample_id_all = 1;	/* affects non RECORD samples */
	/* attr.disabled = 1; */

	return (perf_event_open(&attr, -1, cpu, -1, 0));
}

int
main(int argc, char *argv[])
{
	int *cpu_to_fd, ncpus, nfds, r, i;
	struct pollfd *fds;

	ncpus = get_nprocs_conf();
	cpu_to_fd = calloc(ncpus, sizeof(int));
	if (cpu_to_fd == NULL)
		err(1, "calloc");
	for (i = 0; i < ncpus; i++) {
		cpu_to_fd[i] = open_perf(i);
		if (cpu_to_fd[i] == -1)
			err(1, "can't open perf ring for cpu %d\n", i);
		printf("cpu%-3d fd:%3d\n", i, cpu_to_fd[i]);
	}
	nfds = ncpus;		/* XXX for now */
	fds = calloc(nfds, sizeof(*fds));
	if (fds == NULL)
		err(1, "calloc");
	for (i = 0; i < nfds; i++) {
		fds[i].fd = cpu_to_fd[i];
		fds[i].events = POLLIN;
	}
	/*
	 * XXX this makes no sense, events are always pollable until we drain
	 */
	for (;;) {
		if ((r = poll(fds, ncpus, -1)) == -1)
			err(1, "poll");

		for (i = 0; i < ncpus; i++) {
			char tmp[4096];
			ssize_t n = read(cpu_to_fd[i], tmp, sizeof(tmp));
			printf("cpu%d fd%d n=%zd\n", i, cpu_to_fd[i], n);
		}
		warnx("poll %d\n", r);
		for (i = 0; i < r; i++) {
			if (fds[i].revents & POLLERR)
				errx(1, "fd %d got ERR\n", fds[i].fd);
			if ((fds[i].revents & (POLLIN | POLLHUP)) == 0)
				continue;
			if (fds[i].revents & POLLHUP)
				warnx("fd %d got HUP\n", fds[i].fd);

			char tmp[4096];
			ssize_t n = read(fds[i].fd, tmp, sizeof(tmp));
			printf("fd%d n=%zd\n", fds[i].fd, n);
		}
		sleep(2);
	}

	return (0);
}
