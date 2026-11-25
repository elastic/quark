// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

/*
 * cache-bench measures the CPU and memory quark spends on its process cache
 * while processes come and go, with workloads that leave live processes whose
 * parent or leaders exited. It runs each scenario on a fresh queue and prints
 * one line per scenario to stdout, as a table to compare between builds.
 *
 * The consumer is this process, the workload runs in a child, the generator,
 * which is a subreaper, so it can reap and kill what it leaves behind. The
 * processes of the workload are re-executions of this binary, so it needs
 * nothing else, and also runs in the initramfs of krun.sh.
 *
 * To compare with a tree without relations, build it there with NO_RELATIONS,
 * as:
 *
 *	git worktree add ../quark-main main
 *	git -C ../quark-main submodule update --init
 *	make -C ../quark-main libquark_big.a
 *	cc -O2 -D_GNU_SOURCE -DNO_RELATIONS -I../quark-main \
 *	    -I../quark-main/include -o cache-bench-main cache-bench.c \
 *	    ../quark-main/libquark_big.a
 *
 * Run it as root, with -k for the kprobe backend and -g 0 for no grace time,
 * the output of each run is what to compare.
 */

#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <malloc.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "quark.h"

#define ENV_SELF	"CACHE_BENCH_SELF"
#define PIDFD		100	/* long-lived processes report their pid here */
#define BIGARG		16384	/* args of the worst case, near ARGV_MAX */

#define SP_SETSID	0x1
#define SP_SETPGID	0x2
#define SP_BIG		0x4

struct scenario {
	const char	*name;
	int		 count;	/* units at 100% */
	int		 procs;	/* processes per unit */
	int		 live;	/* long-lived processes per unit */
	const char	*what;
};

static const struct scenario scenarios[] = {
	{ "churn",	2000, 1, 0, "fork, exec and exit" },
	{ "pipeline",	500,  4, 0, "a shell and a three process pipeline" },
	{ "daemon",	1000, 2, 1, "a launcher exits, its daemon stays" },
	{ "login",	500,  3, 2, "a session leader exits, two jobs stay" },
	{ "worst",	200,  6, 1,
	  "a leaf keeps four distinct exited relations, 16 KiB args each" },
	{ "command",	1,    0, 0, "the command after --" },
};

struct sample {
	u64	heap;		/* bytes in use by malloc */
	u64	rss;		/* KiB */
	u64	hwm;		/* KiB */
	u64	cached;		/* processes quark_process_iter sees */
	u64	retained;
	u64	raw;
	u64	lost;
	u64	missed;
	u64	cpu;		/* ns, user and system */
};

static char	**command;

static void
report_pid(void)
{
	pid_t	pid = getpid();

	if (write(PIDFD, &pid, sizeof(pid)) != sizeof(pid))
		err(1, "write");
	close(PIDFD);
}

static void
sleep_forever(void)
{
	report_pid();
	for (;;)
		pause();
}

static pid_t
spawn(const char *path, const char *role, int flags)
{
	static char	 big[BIGARG];
	char		*argv[5];
	const char	*p;
	pid_t		 pid;
	int		 i;

	if ((pid = fork()) == -1)
		err(1, "fork");
	if (pid != 0)
		return (pid);
	if ((flags & SP_SETSID) && setsid() == -1)
		err(1, "setsid");
	if ((flags & SP_SETPGID) && setpgid(0, 0) == -1)
		err(1, "setpgid");
	i = 0;
	p = strrchr(path, '/');
	argv[i++] = (char *)(p != NULL ? p + 1 : path);
	argv[i++] = "-X";
	argv[i++] = (char *)role;
	if (flags & SP_BIG) {
		memset(big, 'x', sizeof(big) - 1);
		argv[i++] = big;
	}
	argv[i] = NULL;
	execv(path, argv);
	err(1, "execv %s", path);
}

static int
read_pid(int fd, pid_t *pid)
{
	return (read(fd, pid, sizeof(*pid)) == sizeof(*pid) ? 0 : -1);
}

/* Spawns n sleepers, their pids are passed on once they exec'd */
static void
spawn_jobs(const char *self, int n)
{
	pid_t	pid;
	int	p[2], out, i;

	if (pipe2(p, O_CLOEXEC) == -1)
		err(1, "pipe2");
	if ((out = fcntl(PIDFD, F_DUPFD_CLOEXEC, 0)) == -1)
		err(1, "fcntl");
	if (dup2(p[1], PIDFD) == -1)
		err(1, "dup2");
	close(p[1]);
	for (i = 0; i < n; i++)
		spawn(self, "sleep", 0);
	close(PIDFD);
	for (i = 0; i < n; i++) {
		if (read_pid(p[0], &pid) == -1)
			errx(1, "lost a pid");
		if (write(out, &pid, sizeof(pid)) != sizeof(pid))
			err(1, "write");
	}
}

static void
wait1(pid_t pid)
{
	while (waitpid(pid, NULL, 0) == -1)
		if (errno != EINTR)
			err(1, "waitpid");
}

static void
wait_all(void)
{
	while (wait(NULL) != -1 || errno == EINTR)
		;
}

/*
 * The processes of the workload, deterministic: a process exits after the
 * ones it relates to exec'd. The worst case is a chain where each stage
 * waits for the next to exec, so it is related to it, and exits after it:
 * sshd makes entry an entry leader, session calls setsid, group setpgid,
 * parent forks the leaf, which doesn't exec.
 */
static int
role(const char *name)
{
	const char	*self;
	pid_t		 pid;

	if ((self = getenv(ENV_SELF)) == NULL)
		errx(1, "%s not set", ENV_SELF);
	if (!strcmp(name, "noop"))
		return (0);
	if (!strcmp(name, "sleep"))
		sleep_forever();
	if (!strcmp(name, "shell")) {
		spawn(self, "noop", 0);
		spawn(self, "noop", 0);
		spawn(self, "noop", 0);
		wait_all();
	} else if (!strcmp(name, "launcher")) {
		/* As daemon(3), the daemon doesn't exec */
		if ((pid = fork()) == -1)
			err(1, "fork");
		if (pid == 0) {
			if (setsid() == -1)
				err(1, "setsid");
			sleep_forever();
		}
	} else if (!strcmp(name, "login"))
		/* As a shell, the jobs exec before it exits */
		spawn_jobs(self, 2);
	else if (!strcmp(name, "sshd"))
		wait1(spawn(self, "entry", SP_SETSID | SP_BIG));
	else if (!strcmp(name, "entry"))
		wait1(spawn(self, "session", SP_SETSID | SP_BIG));
	else if (!strcmp(name, "session"))
		wait1(spawn(self, "group", SP_SETPGID | SP_BIG));
	else if (!strcmp(name, "group"))
		wait1(spawn(self, "parent", SP_BIG));
	else if (!strcmp(name, "parent")) {
		if ((pid = fork()) == -1)
			err(1, "fork");
		if (pid == 0)
			sleep_forever();
	} else
		errx(1, "unknown role %s", name);

	return (0);
}

static void
copy_file(const char *from, const char *to)
{
	char	buf[65536];
	ssize_t	n;
	int	in, out;

	if ((in = open(from, O_RDONLY | O_CLOEXEC)) == -1)
		err(1, "open %s", from);
	if ((out = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
	    0755)) == -1)
		err(1, "open %s", to);
	while ((n = read(in, buf, sizeof(buf))) > 0)
		if (write(out, buf, n) != n)
			err(1, "write %s", to);
	if (n == -1)
		err(1, "read %s", from);
	close(in);
	close(out);
}

/*
 * Runs the scenario, waits for the consumer to tear it down, then kills what
 * stayed and exits.
 */
static void
generator(const struct scenario *sc, int units, int ctl, int st)
{
	const char	*self;
	char		 tmpdir[] = "/tmp/cache-bench.XXXXXX", sshd[PATH_MAX];
	pid_t		*live, pid;
	int		 pids[2], i, j, nlive;
	char		 c;

	if (prctl(PR_SET_CHILD_SUBREAPER, 1) == -1)
		err(1, "prctl");
	self = getenv(ENV_SELF);
	if (pipe2(pids, O_CLOEXEC) == -1)
		err(1, "pipe2");
	if (dup2(pids[1], PIDFD) == -1)
		err(1, "dup2");
	close(pids[1]);
	if ((live = calloc(units * sc->live + 1, sizeof(*live))) == NULL)
		err(1, "calloc");
	if (!strcmp(sc->name, "worst")) {
		if (mkdtemp(tmpdir) == NULL)
			err(1, "mkdtemp");
		snprintf(sshd, sizeof(sshd), "%s/sshd", tmpdir);
		copy_file(self, sshd);
	}
	if (read(ctl, &c, 1) != 1)
		exit(1);

	nlive = 0;
	for (i = 0; i < units; i++) {
		if (!strcmp(sc->name, "churn"))
			wait1(spawn(self, "noop", 0));
		else if (!strcmp(sc->name, "pipeline"))
			wait1(spawn(self, "shell", 0));
		else if (!strcmp(sc->name, "daemon"))
			wait1(spawn(self, "launcher", 0));
		else if (!strcmp(sc->name, "login"))
			wait1(spawn(self, "login", SP_SETSID));
		else if (!strcmp(sc->name, "worst"))
			wait1(spawn(sshd, "sshd", 0));
		else if (!strcmp(sc->name, "command")) {
			if ((pid = fork()) == -1)
				err(1, "fork");
			if (pid == 0) {
				close(PIDFD);
				execvp(command[0], command);
				err(1, "execvp %s", command[0]);
			}
			wait1(pid);
		}
		for (j = 0; j < sc->live; j++)
			if (read_pid(pids[0], &live[nlive++]) == -1)
				errx(1, "lost a pid");
	}

	if (write(st, "r", 1) != 1 || read(ctl, &c, 1) != 1)
		exit(1);
	for (i = 0; i < nlive; i++)
		kill(live[i], SIGKILL);
	wait_all();
	if (!strcmp(sc->name, "worst")) {
		unlink(sshd);
		rmdir(tmpdir);
	}
	exit(0);
}

static u64
now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ((u64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static u64
heap_inuse(void)
{
#if defined(__GLIBC__) && (__GLIBC__ > 2 || __GLIBC_MINOR__ >= 33)
	struct mallinfo2	mi = mallinfo2();

	return (mi.uordblks + mi.hblkhd);
#elif defined(__GLIBC__)
	struct mallinfo		mi = mallinfo();

	return ((unsigned)mi.uordblks + (unsigned)mi.hblkhd);
#else
	return (0);
#endif
}

static void
read_status(u64 *rss, u64 *hwm)
{
	FILE		*f;
	char		 line[256];
	unsigned long	 v;

	*rss = *hwm = 0;
	if ((f = fopen("/proc/self/status", "r")) == NULL)
		return;
	while (fgets(line, sizeof(line), f) != NULL) {
		if (sscanf(line, "VmRSS: %lu", &v) == 1)
			*rss = v;
		else if (sscanf(line, "VmHWM: %lu", &v) == 1)
			*hwm = v;
	}
	fclose(f);
}

/*
 * Runs of our BPF programs the kernel skipped, as one was already running on
 * that CPU, their events never arrive, see recursion_misses in bpftool-prog(8).
 */
static u64
bpf_missed(void)
{
	DIR		*d;
	struct dirent	*de;
	FILE		*f;
	char		 path[PATH_MAX], line[256];
	unsigned long long v;
	u64		 n;

	n = 0;
	if ((d = opendir("/proc/self/fdinfo")) == NULL)
		return (0);
	while ((de = readdir(d)) != NULL) {
		snprintf(path, sizeof(path), "/proc/self/fdinfo/%s",
		    de->d_name);
		if ((f = fopen(path, "r")) == NULL)
			continue;
		while (fgets(line, sizeof(line), f) != NULL)
			if (sscanf(line, "recursion_misses: %llu", &v) == 1)
				n += v;
		fclose(f);
	}
	closedir(d);

	return (n);
}

static void
take(struct quark_queue *qq, struct sample *s)
{
	struct quark_queue_stats	 stats;
	struct quark_process_iter	 qi;
	struct rusage			 ru;

	s->heap = heap_inuse();
	read_status(&s->rss, &s->hwm);
	s->cached = 0;
	quark_process_iter_init(&qi, qq);
	while (quark_process_iter_next(&qi) != NULL)
		s->cached++;
	quark_queue_get_stats(qq, &stats);
	s->raw = stats.insertions;
	s->lost = stats.lost;
	s->missed = bpf_missed();
#ifdef NO_RELATIONS
	s->retained = 0;
#else
	s->retained = stats.retained_processes;
#endif
	getrusage(RUSAGE_SELF, &ru);
	s->cpu = ((u64)ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000000000 +
	    ((u64)ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) * 1000;
}

struct counts {
	u64	pevents;	/* process events with a parent pid */
	u64	parents;	/* of which the parent is known */
	int	ecs;
};

/*
 * Get events until fd says something, or until deadline if fd is -1. Returns
 * what fd said, 0 on EOF.
 */
static int
drain(struct quark_queue *qq, struct counts *d, int fd, u64 deadline)
{
	const struct quark_event	*qev;
	const struct quark_process	*qp;
	struct pollfd			 pfd;
	char				*buf, c;
	size_t				 len;

	for (;;) {
		if ((qev = quark_queue_get_event(qq)) != NULL) {
			qp = qev->process;
			if (qp != NULL && (qp->flags & QUARK_F_PROC) &&
			    qp->proc_ppid != 0 &&
			    (qev->events & (QUARK_EV_FORK | QUARK_EV_EXEC |
			    QUARK_EV_EXIT))) {
				d->pevents++;
#ifdef NO_RELATIONS
				if (quark_process_lookup(qq,
				    qp->proc_ppid) != NULL)
#else
				if (qp->parent != NULL)
#endif
					d->parents++;
			}
			if (d->ecs && quark_event_to_ecs(qq, qev, &buf,
			    &len) == 0)
				free(buf);
			continue;
		}
		if (fd != -1) {
			pfd.fd = fd;
			pfd.events = POLLIN;
			if (poll(&pfd, 1, 0) == 1)
				return (read(fd, &c, 1) == 1 ? c : 0);
		} else if (now_ms() >= deadline)
			return (0);
		if (quark_queue_block(qq) == -1 && errno != EINTR)
			err(1, "quark_queue_block");
	}
}

static void
settle(struct quark_queue *qq, struct counts *d, struct quark_queue_attr *qa)
{
	drain(qq, d, -1, now_ms() + qa->cache_grace_time + qa->hold_time +
	    1000);
}

#define DIFF(_a, _b)	((long long)(_a) - (long long)(_b))

static void
run(const struct scenario *sc, int units, struct quark_queue_attr *qa,
    int ecs)
{
	struct quark_queue	 qq;
	struct sample		 base, live, end;
	struct counts		 d;
	int			 ctl[2], st[2], fd;
	pid_t			 gen;
	char			 retained[64];

	if (pipe2(ctl, O_CLOEXEC) == -1 || pipe2(st, O_CLOEXEC) == -1)
		err(1, "pipe2");
	/* Before the queue, so the generator doesn't hold its fds */
	if ((gen = fork()) == -1)
		err(1, "fork");
	if (gen == 0) {
		close(ctl[1]);
		close(st[0]);
		generator(sc, units, ctl[0], st[1]);
	}
	close(ctl[0]);
	close(st[1]);

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");
	bzero(&d, sizeof(d));
	d.ecs = ecs;
	drain(&qq, &d, -1, now_ms() + 1000);
	bzero(&d, sizeof(d));
	d.ecs = ecs;
	/* Peak RSS of the scenario, see proc(5) */
	if ((fd = open("/proc/self/clear_refs", O_WRONLY)) != -1) {
		if (write(fd, "5", 1) != 1)
			warn("clear_refs");
		close(fd);
	}
	take(&qq, &base);

	if (write(ctl[1], "g", 1) != 1)
		err(1, "write");
	if (drain(&qq, &d, st[0], 0) != 'r')
		errx(1, "%s: generator failed", sc->name);
	settle(&qq, &d, qa);
	take(&qq, &live);
	if (write(ctl[1], "t", 1) != 1)
		err(1, "write");
	drain(&qq, &d, st[0], 0);
	wait1(gen);
	settle(&qq, &d, qa);
	take(&qq, &end);
	quark_queue_close(&qq);
	close(ctl[1]);
	close(st[0]);

#ifdef NO_RELATIONS
	snprintf(retained, sizeof(retained), "%8s %6s", "-", "-");
#else
	snprintf(retained, sizeof(retained), "%8llu %6llu",
	    (unsigned long long)live.retained,
	    (unsigned long long)end.retained);
#endif
	printf("%-9s %6d %7llu %5llu %6llu %7llu %6.1f %7llu %s %8lld %8lld "
	    "%8lld %8lld\n",
	    sc->name, units * sc->procs,
	    (unsigned long long)(end.raw - base.raw),
	    (unsigned long long)(end.lost - base.lost),
	    (unsigned long long)(end.missed - base.missed),
	    end.raw > base.raw ?
	    (unsigned long long)((end.cpu - base.cpu) / (end.raw - base.raw)) :
	    0,
	    d.pevents ? 100.0 * d.parents / d.pevents : 0.0,
	    (unsigned long long)live.cached, retained,
	    DIFF(live.heap, base.heap) / 1024, DIFF(end.heap, base.heap) / 1024,
	    DIFF(live.rss, base.rss), DIFF(end.hwm, base.rss));
	fflush(stdout);
}

static void
usage(void)
{
	fprintf(stderr, "usage: cache-bench [-Ek] [-g grace_ms] [-s scenario]"
	    " [-x percent] [-- command [arg ...]]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct quark_queue_attr	 qa;
	struct utsname		 un;
	const struct scenario	*sc;
	char			 self[PATH_MAX];
	const char		*only[8], *backend;
	ssize_t			 n;
	int			 ch, i, j, nonly, ecs, percent;

	if (argc >= 3 && !strcmp(argv[1], "-X"))
		return (role(argv[2]));

	quark_queue_default_attr(&qa);
	qa.flags |= QQ_ENTRY_LEADER;
	nonly = ecs = 0;
	percent = 100;
	while ((ch = getopt(argc, argv, "Eg:ks:x:")) != -1) {
		switch (ch) {
		case 'E':
			ecs = 1;
			break;
		case 'g':
			qa.cache_grace_time = atoi(optarg);
			break;
		case 'k':
			qa.flags &= ~(QQ_EBPF | QQ_NOVA);
			qa.flags |= QQ_KPROBE;
			break;
		case 's':
			if (nonly == (int)(sizeof(only) / sizeof(only[0])))
				usage();
			only[nonly++] = optarg;
			break;
		case 'x':
			if ((percent = atoi(optarg)) <= 0)
				usage();
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 0)
		command = argv;

	if ((n = readlink("/proc/self/exe", self, sizeof(self) - 1)) == -1)
		err(1, "readlink");
	self[n] = 0;
	if (setenv(ENV_SELF, self, 1) == -1)
		err(1, "setenv");
	if (uname(&un) == -1)
		err(1, "uname");
	if (qa.flags & QQ_KPROBE)
		backend = "kprobe";
	else
		backend = getenv("QUARK_BPF_KPROBE") ? "ebpf-kprobe" : "ebpf";

	printf("# cache-bench %s, %s %s, %s, grace %d ms, hold %d ms, "
	    "ecs %s, scale %d%%\n",
#ifdef NO_RELATIONS
	    "without relations",
#else
	    "with relations",
#endif
	    un.release, un.machine, backend, qa.cache_grace_time,
	    qa.hold_time, ecs ? "yes" : "no", percent);
	printf("#\n"
	    "# procs: processes the workload starts\n"
	    "# raw: raw events, lost: lost ones\n"
	    "# missed: runs of BPF programs the kernel skipped, their events "
	    "never arrive\n"
	    "#         and a process whose exit is missed stays cached\n"
	    "# ns/raw: cpu of this process per raw event, user and system\n"
	    "# parent: %% of fork, exec and exit events with a known parent\n"
	    "# cached: processes quark_process_iter(3) sees, while the "
	    "workload lives\n"
	    "# retained: retained_processes then, after: once it ended\n"
	    "# heap, rss: KiB more than before the workload, while it lives\n"
	    "# heap=: KiB more than before, once it ended\n"
	    "# peak: peak rss during the scenario, KiB more than before\n"
	    "#\n");
	for (i = 0; i < (int)(sizeof(scenarios) / sizeof(scenarios[0])); i++)
		printf("# %-9s %s\n", scenarios[i].name, scenarios[i].what);
	printf("#\n");
	printf("%-9s %6s %7s %5s %6s %7s %6s %7s %8s %6s %8s %8s %8s %8s\n",
	    "#scenario", "procs", "raw", "lost", "missed", "ns/raw", "parent",
	    "cached",
	    "retained", "after", "heap", "heap=", "rss", "peak");
	fflush(stdout);

	for (i = 0; i < (int)(sizeof(scenarios) / sizeof(scenarios[0]));
	    i++) {
		sc = &scenarios[i];
		if (nonly > 0) {
			for (j = 0; j < nonly; j++)
				if (!strcmp(only[j], sc->name))
					break;
			if (j == nonly)
				continue;
		}
		if (!strcmp(sc->name, "command")) {
			if (command == NULL)
				continue;
			run(sc, 1, &qa, ecs);
		} else
			run(sc, sc->count * percent / 100 > 0 ?
			    sc->count * percent / 100 : 1, &qa, ecs);
	}

	return (0);
}
