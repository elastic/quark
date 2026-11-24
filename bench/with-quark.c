// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

/*
 * with-quark: run a command while a quark queue is open and record
 * CPU library cost.
 *
 * We open the queue, start the command, then sit on CPU 0 taking every event
 * and throwing it away until the command exits, as the cheapest possible user
 * of the library would. The CPU time we burn doing that is the cost of quark
 * in userspace for whatever the command did to the machine.
 *
 * What the queue does is chosen as in quark-mon(8), by the same letters: the
 * backend (-b, -k, -n), the features (-B, -e, -F, -G, -g, -H, -L, -N, -S,
 * -T, -t, -U, -u), their settings (-A, -f, -I, -l) and -v.
 *
 * Every letter belongs to quark-mon, so to avoid collisions our own options
 * are long ones: we measure from the end of the warm-up (--warmup) for as
 * long as told (--duration), or until the command exits, and --prog-stats
 * has the BPF programs timed, see below.
 *
 * Results are "name value" lines on stdout, after whatever the command wrote:
 *
 *   wall_ms      how long we measured for, without the wait after the
 *                command exits (see below). It can be 100 ms more than told,
 *                as we only look at the clock when quark wakes us up
 *   cpu_ms       our cpu time, user and system
 *   cpu_percent  the same in percent of one core, over the time measured
 *   events       events we were given
 *   lost         events lost by the ring, plus packets refused by a full
 *                flow map
 *
 * That covers the userspace CPU cost. Most of what quark costs in the kernel
 * is usually not ours to pay: quark BPF programs run in the context of whoever
 * opens the file or processes the packet on egress/ingress. With --prog-stats
 * we have the kernel time all the BPF programs while we measure
 * (BPF_ENABLE_STATS, Linux 5.8) and add two lines for each program that ran:
 *
 *   prog_runs.NAME  how many times it ran
 *   prog_ns.NAME    how long a run took on average
 *
 * Quark holds an event for a while before handing it over (hold_time, one
 * second). If the command exits while we measure, we stay that much longer
 * so that a whole command is counted and paid for in full: the events quark
 * hands us during that second count in events, and the CPU time we spend
 * taking them in cpu_ms. wall_ms does not include that second, it ends where
 * the command did, and so does the timing of the programs. Flows are the
 * exception, and those of the last aggregation period are never drained (to
 * avoid delaying exit even further, as aggregation periods can be long).
 *
 * If --duration is given and the command is still running when that time is
 * up, we stop measuring right there, do not wait the extra second, and end
 * the command with SIGTERM. Only the command itself is signaled, not what it
 * may have started. If it is still there five seconds later it gets a
 * SIGKILL: the results are printed all the same, but we exit with an error.
 *
 * Otherwise our exit status is that of the command, and success if it died
 * of our SIGTERM. Should we die first, the command gets a SIGTERM as well.
 */

#include <sys/prctl.h>
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "quark.h"
#include "quark_internal.h"

#define KILL_GRACE_NS	(5 * NS_PER_S)	/* from SIGTERM to SIGKILL */
#define MAX_PROGS	256
#define PROG_NAME_LEN	128

/*
 * Our own options. They start past any character, so that none can collide
 * with a quark-mon option, present or future.
 */
enum {
	OPT_DURATION = UCHAR_MAX + 1,
	OPT_PROG_STATS,
	OPT_WARMUP
};

static const struct option	longopts[] = {
	{ "duration",	required_argument,	NULL,	OPT_DURATION },
	{ "prog-stats",	no_argument,		NULL,	OPT_PROG_STATS },
	{ "warmup",	required_argument,	NULL,	OPT_WARMUP },
	{ NULL,		0,			NULL,	0 }
};

/*
 * A BPF program of the queue. The counters are what the kernel had when we
 * started measuring, then what it added until we stopped.
 */
struct prog {
	int	fd;
	char	name[PROG_NAME_LEN];
	u64	run_time_ns;
	u64	run_cnt;
};

static struct prog		progs[MAX_PROGS];
static int			nprogs;
static volatile sig_atomic_t	child_exited;

static void
sigchld(int sig)
{
	child_exited = 1;
}

static u64
now(clockid_t clock)
{
	struct timespec	ts;

	if (clock_gettime(clock, &ts) == -1)
		err(1, "clock_gettime");

	return ((u64)ts.tv_sec * NS_PER_S + ts.tv_nsec);
}

/*
 * The kernel keeps 15 characters of a program's name and many of ours
 * have the same prefix. The full program name is in the BTF, as the
 * name of its first function. If we can't fetch that, 15 chars it is.
 */
static void
prog_name(struct prog *p)
{
	struct bpf_prog_info	 info;
	struct bpf_func_info	 func;
	struct btf		*btf;
	const struct btf_type	*t;
	const char		*name;
	__u32			 len, btf_id;

	bzero(&info, sizeof(info));
	len = sizeof(info);
	/* libbpf returns -errno, and leaves errno set */
	if (bpf_obj_get_info_by_fd(p->fd, &info, &len) < 0)
		err(1, "bpf_obj_get_info_by_fd");
	strlcpy(p->name, info.name, sizeof(p->name));
	if ((btf_id = info.btf_id) == 0 || info.nr_func_info == 0)
		return;

	/* Again, now with room for the first function */
	bzero(&info, sizeof(info));
	bzero(&func, sizeof(func));
	len = sizeof(info);
	info.nr_func_info = 1;
	info.func_info_rec_size = sizeof(func);
	info.func_info = (__u64)(unsigned long)&func;
	if (bpf_obj_get_info_by_fd(p->fd, &info, &len) < 0 ||
	    info.nr_func_info == 0)
		return;
	if ((btf = btf__load_from_kernel_by_id(btf_id)) == NULL)
		return;
	if ((t = btf__type_by_id(btf, func.type_id)) != NULL &&
	    (name = btf__name_by_offset(btf, t->name_off)) != NULL &&
	    *name != 0)
		strlcpy(p->name, name, sizeof(p->name));
	btf__free(btf);
}

/*
 * The queue doesn't say which programs it loaded, but each one is a file
 * descriptor of ours, and those we can list.
 */
static void
progs_find(void)
{
	DIR		*dir;
	struct dirent	*d;
	char		 path[PATH_MAX], target[64];
	ssize_t		 n;

	if ((dir = opendir("/proc/self/fd")) == NULL)
		err(1, "opendir /proc/self/fd");
	while ((d = readdir(dir)) != NULL && nprogs < MAX_PROGS) {
		snprintf(path, sizeof(path), "/proc/self/fd/%s", d->d_name);
		if ((n = readlink(path, target, sizeof(target) - 1)) == -1)
			continue;
		target[n] = 0;
		if (strcmp(target, "anon_inode:bpf-prog"))
			continue;
		progs[nprogs].fd = atoi(d->d_name);
		prog_name(&progs[nprogs++]);
	}
	closedir(dir);
}

static void
progs_read(int stop)
{
	struct bpf_prog_info	 info;
	struct prog		*p;
	__u32			 len;

	for (p = progs; p < progs + nprogs; p++) {
		bzero(&info, sizeof(info));
		len = sizeof(info);
		if (bpf_obj_get_info_by_fd(p->fd, &info, &len) < 0)
			err(1, "bpf_obj_get_info_by_fd");
		p->run_time_ns = info.run_time_ns - (stop ? p->run_time_ns : 0);
		p->run_cnt = info.run_cnt - (stop ? p->run_cnt : 0);
	}
}

static int
number(const char *what, const char *s, int min)
{
	const char	*errstr;
	int		 v;

	v = strtonum(s, min, INT_MAX, &errstr);
	if (errstr != NULL)
		errx(1, "invalid %s: %s", what, errstr);

	return (v);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-BbeFGgHkLNnSTtUuv] [-A agg_ms] "
	    "[-f max_flows] [-I idle_ms]\n"
	    "\t    [-l maxlength] [--duration ms] [--prog-stats] [--warmup ms]\n"
	    "\t    command [argument ...]\n",
	    program_invocation_short_name);

	exit(1);
}

int
main(int argc, char *argv[])
{
	struct quark_queue		*qq;
	struct quark_queue_attr		 qa;
	struct quark_queue_stats	 st;
	struct sigaction		 sa;
	cpu_set_t			 set;
	pid_t				 child, parent;
	struct prog			*p;
	int				 ch, measuring, killed, prog_stats, status;
	u64				 cpu_ns, wall_ns, t0, warmup, duration;
	u64				 events, deadline;

	quark_queue_default_attr(&qa);
	qa.flags &= ~(QQ_EBPF | QQ_KPROBE | QQ_NOVA);
	warmup = 0;
	duration = UINT64_MAX;
	prog_stats = 0;

	while ((ch = getopt_long(argc, argv, "+A:BbeFf:GgHI:kLl:NnSTtUuv",
	    longopts, NULL)) != -1) {
		switch (ch) {
		/*
		 * These are quark-mon's
		 */
		case 'A':
			qa.udp_agg_time = number("udp aggregation time",
			    optarg, 1);
			qa.flags |= QQ_UDP_FLOW;
			break;
		case 'B':
			qa.flags |= QQ_BYPASS;
			break;
		case 'b':
			qa.flags |= QQ_EBPF;
			break;
		case 'e':
			qa.flags |= QQ_ENTRY_LEADER;
			break;
		case 'F':
			qa.flags |= QQ_FILE;
			break;
		case 'f':
			qa.udp_max_flows = number("udp max flows", optarg, 1);
			qa.flags |= QQ_UDP_FLOW;
			break;
		case 'G':
			qa.flags |= QQ_GETPID;
			break;
		case 'g':
			qa.flags |= QQ_MIN_AGG;
			break;
		case 'H':
			qa.flags |= QQ_SHM;
			break;
		case 'I':
			qa.udp_idle_time = number("udp idle time", optarg, 1);
			qa.flags |= QQ_UDP_FLOW;
			break;
		case 'k':
			qa.flags |= QQ_KPROBE;
			break;
		case 'L':
			qa.flags |= QQ_MODULE_LOAD;
			break;
		case 'l':
			qa.max_length = number("max length", optarg, 1);
			break;
		case 'N':
			qa.flags |= QQ_DNS;
			break;
		case 'n':
			qa.flags |= QQ_NOVA;
			break;
		case 'S':
			qa.flags |= QQ_SOCK_CONN;
			break;
		case 'T':
			qa.flags |= QQ_PTRACE;
			break;
		case 't':
			qa.flags |= QQ_THREAD_EVENTS;
			break;
		case 'U':
			qa.flags |= QQ_UDP_FLOW;
			break;
		case 'u':
			qa.flags |= QQ_MPROTECT;
			break;
		case 'v':
			quark_verbose++;
			break;
		/*
		 * These are ours
		 */
		case OPT_DURATION:
			duration = number("duration", optarg, 1) * NS_PER_MS;
			break;
		case OPT_PROG_STATS:
			prog_stats = 1;
			break;
		case OPT_WARMUP:
			warmup = number("warm-up", optarg, 0) * NS_PER_MS;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc == 0)
		usage();

	/* Ebpf unless told otherwise, as quark-mon */
	if ((qa.flags & (QQ_KPROBE | QQ_NOVA)) == 0)
		qa.flags |= QQ_EBPF;

	/*
	 * We don't want to be told when it is stopped or continued,
	 * say by a ^Z, and take it for dead.
	 */
	bzero(&sa, sizeof(sa));
	sa.sa_handler = sigchld;
	sa.sa_flags = SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		err(1, "sigaction");

	/* The probes are in place before the command starts */
	if ((qq = calloc(1, sizeof(*qq))) == NULL)
		err(1, "calloc");
	if (quark_queue_open(qq, &qa) != 0)
		err(1, "quark_queue_open");
	/* The kernel times programs for as long as we hold on to this */
	if (prog_stats) {
		if (bpf_enable_stats(BPF_STATS_RUN_TIME) < 0)
			err(1, "bpf_enable_stats");
		progs_find();
	}

	parent = getpid();
	if ((child = fork()) == -1)
		err(1, "fork");
	else if (child == 0) {
		/*
		 * A command told to run until stopped must not outlive us.
		 * The signal only comes if we die from here on, so check
		 * that we didn't just before.
		 */
		if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1)
			err(1, "prctl");
		if (getppid() != parent)
			_exit(1);
		execvp(argv[0], argv);
		err(127, "%s", argv[0]);
	}

	/* Only now, the command must not inherit our cpu */
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	if (sched_setaffinity(0, sizeof(set), &set) == -1)
		err(1, "sched_setaffinity");

	measuring = 0;
	cpu_ns = events = 0;
	t0 = now(CLOCK_MONOTONIC);
	for (;;) {
		if (!measuring && now(CLOCK_MONOTONIC) - t0 >= warmup) {
			measuring = 1;
			progs_read(0);
			cpu_ns = now(CLOCK_PROCESS_CPUTIME_ID);
			t0 = now(CLOCK_MONOTONIC);
		} else if (measuring && now(CLOCK_MONOTONIC) - t0 >= duration)
			break;
		/*
		 * Only after the above: a command that was quicker to exit
		 * than we were to get here is measured all the same.
		 */
		if (child_exited)
			break;
		/* Wakes up on events, SIGCHLD, or after 100ms */
		if (quark_queue_get_event(qq) == NULL)
			quark_queue_block(qq);
		else if (measuring)
			events++;
	}
	if (!measuring)
		errx(1, "%s exited during the warm-up", argv[0]);
	wall_ns = now(CLOCK_MONOTONIC) - t0;
	progs_read(1);

	/*
	 * The command is gone, but what it did last is still held by quark.
	 * That is part of its bill, though the wait is not.
	 */
	if (child_exited) {
		deadline = now(CLOCK_MONOTONIC) + qa.hold_time * NS_PER_MS;
		for (;;) {
			while (quark_queue_get_event(qq) != NULL)
				events++;
			if (now(CLOCK_MONOTONIC) >= deadline)
				break;
			quark_queue_block(qq);
		}
	}
	cpu_ns = now(CLOCK_PROCESS_CPUTIME_ID) - cpu_ns;

	/*
	 * We have what we came for, the command can go. Keep the ring empty
	 * while it does.
	 */
	killed = 0;
	deadline = 0;
	if (!child_exited) {
		if (kill(child, SIGTERM) == -1)
			err(1, "kill");
		killed = SIGTERM;
		deadline = now(CLOCK_MONOTONIC) + KILL_GRACE_NS;
	}
	while (!child_exited) {
		if (killed == SIGTERM && now(CLOCK_MONOTONIC) >= deadline) {
			if (kill(child, SIGKILL) == -1)
				err(1, "kill");
			killed = SIGKILL;
		}
		if (quark_queue_get_event(qq) == NULL)
			quark_queue_block(qq);
	}

	quark_queue_get_stats(qq, &st);
	printf("wall_ms %.3f\n", (double)wall_ns / NS_PER_MS);
	printf("cpu_ms %.3f\n", (double)cpu_ns / NS_PER_MS);
	printf("cpu_percent %.3f\n", 100.0 * cpu_ns / wall_ns);
	printf("events %llu\n", (unsigned long long)events);
	printf("lost %llu\n", (unsigned long long)(st.lost + st.udp_flow_lost));

	for (p = progs; p < progs + nprogs; p++) {
		if (p->run_cnt == 0)
			continue;
		printf("prog_runs.%s %llu\n", p->name,
		    (unsigned long long)p->run_cnt);
		printf("prog_ns.%s %.1f\n", p->name,
		    (double)p->run_time_ns / p->run_cnt);
	}

	quark_queue_close(qq);
	free(qq);

	if (waitpid(child, &status, 0) == -1)
		err(1, "waitpid");
	if (killed == SIGKILL)
		errx(1, "%s ignored SIGTERM, killed", argv[0]);
	if (killed && WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM)
		return (0);
	if (!WIFEXITED(status))
		errx(1, "%s didn't exit cleanly", argv[0]);

	return (WEXITSTATUS(status));
}
