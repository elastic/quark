// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <sys/wait.h>

#include "quark.h"

#define MAN_QUARK_MON
#include "manpages.h"

static int gotsigint;

static void
dump_stats(struct quark_queue *qq)
{
	struct quark_queue_stats	s;

	quark_queue_get_stats(qq, &s);
	putchar('\n');
	printf(
	    "%14s"
	    "%14s"
	    "%14s"
	    "%14s"
	    "%14s"
	    "%14s",
	    "insertions",
	    "removals",
	    "aggs",
	    "non-aggs",
	    "lost",
	    "gc-cols"
	);
	putchar('\n');
	printf(
	    "%14llu"
	    "%14llu"
	    "%14llu"
	    "%14llu"
	    "%14llu"
	    "%14llu",
	    s.insertions, s.removals, s.aggregations,
	    s.non_aggregations, s.lost, s.garbage_collections);
	putchar('\n');
}

static const char *
fetch_backend(struct quark_queue *qq)
{
	struct quark_queue_stats	s;

	quark_queue_get_stats(qq, &s);

	return (s.backend == QQ_EBPF ? "ebpf" :
	    s.backend == QQ_KPROBE ? "kprobe" :
	    "invalid");
}

static void
sigint_handler(int sig)
{
	gotsigint = 1;
}

static void
priv_drop(void)
{
#ifdef NO_PRIVDROP
	err(1, "built with NO_PRIVDROP");
#else
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
#endif
}

static void
display_version(void)
{
	printf("%s-%s\n", program_invocation_short_name, QUARK_VERSION);
	printf("License: Apache-2.0\n");
	printf("Copyright (c) 2024 Elastic NV\n");

	exit(0);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s -h\n", program_invocation_short_name);
	fprintf(stderr, "usage: %s [-BbDeFkMNSstv] "
	    "[-C filename ] [-K kubeconfig] [-l maxlength] [-m maxnodes] [-P ppid]\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s -V\n", program_invocation_short_name);

	exit(1);
}

static void
print_dump(struct quark_queue *qq, const struct quark_event *qev)
{
	quark_event_dump(qev, stdout);
}

static void
print_ecs(struct quark_queue *qq, const struct quark_event *qev)
{
	char	*ecs_buf;
	size_t	 ecs_buf_len;

	if (quark_event_to_ecs(qq, qev, &ecs_buf, &ecs_buf_len) == -1)
		qwarnx("quark_event_to_ecs");
	else {
		printf("%s\n", ecs_buf);
		fflush(stdout);
		free(ecs_buf);
	}
}

int
main(int argc, char *argv[])
{
	int				 ch, maxnodes;
	int				 do_priv_drop, do_snap;
	int				 benchmark, lflag;
	u32				 filter_ppid;
	struct quark_queue		*qq;
	struct quark_queue_attr		 qa;
	const struct quark_event	*qev;
	struct sigaction		 sigact;
	FILE				*graph_by_time, *graph_by_pidtime, *graph_cache;
	struct timespec			 bench_stamp, now;
	pid_t				 kube_talker_pid;
	const char			*kube_config;
	void 				(*print_event)(struct quark_queue *, const struct quark_event *);

	quark_queue_default_attr(&qa);
	qa.flags &= ~QQ_ALL_BACKENDS;
	maxnodes = -1;
	do_priv_drop = 0;
	filter_ppid = 0;
	do_snap = 1;
	graph_by_time = graph_by_pidtime = graph_cache = NULL;
	lflag = 0;
	benchmark = 0;
	kube_config = NULL;
	print_event = print_dump;

	while ((ch = getopt(argc, argv, "BbC:DEeFghK:kl:Mm:NP:tSsvV")) != -1) {
		const char *errstr;

		switch (ch) {
		case 'B':
			qa.flags |= QQ_BYPASS;
			break;
		case 'b':
			qa.flags |= QQ_EBPF;
			break;
		case 'C':
			graph_cache = fopen(optarg, "w");
			if (graph_cache == NULL)
				err(1, "fopen %s", optarg);
			break;
		case 'D':
			do_priv_drop = 1;
			break;
		case 'e':
			qa.flags |= QQ_ENTRY_LEADER;
			break;
		case 'E':
			print_event = print_ecs;
			break;
		case 'F':
			qa.flags |= QQ_FILE;
			break;
		case 'g':
			qa.flags |= QQ_MIN_AGG;
			break;
		case 'h':
			if (isatty(STDOUT_FILENO))
				display_man();
			else
				usage();
			break;	/* NOTREACHED */
		case 'K':
			kube_config = optarg;
			break;
		case 'k':
			qa.flags |= QQ_KPROBE;
			break;
		case 'l':
			if (optarg == NULL)
				usage();
			qa.max_length = strtonum(optarg, 1, INTMAX_MAX,
			    &errstr);
			if (errstr != NULL)
				errx(1, "invalid max length: %s", errstr);
			lflag = 1;
			break;
		case 'm':
			if (optarg == NULL)
				usage();
			maxnodes = strtonum(optarg, 1, 2000000, &errstr);
			if (errstr != NULL)
				errx(1, "invalid maxnodes: %s", errstr);
			/* open graphviz files before priv_drop */
			graph_by_time = fopen("quark_by_time.dot", "w");
			if (graph_by_time == NULL)
				err(1, "fopen");
			graph_by_pidtime = fopen("quark_by_pidtime.dot", "w");
			if (graph_by_pidtime == NULL)
				err(1, "fopen");
			break;
		case 'M':
			benchmark = 1;
			break;
		case 'N':
			qa.flags |= QQ_DNS;
			break;
		case 'P':
			if (optarg == NULL)
				usage();
			filter_ppid = strtonum(optarg, 1, UINT32_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "invalid ppid: %s", errstr);
			break;
		case 's':
			do_snap = 0;
			break;
		case 'S':
			qa.flags |= QQ_SOCK_CONN;
			break;
		case 't':
			qa.flags |= QQ_THREAD_EVENTS;
			break;
		case 'v':
			quark_verbose++;
			break;
		case 'V':
			display_version();
			break;
		default:
			usage();
		}
	}

	if (benchmark) {
		if (clock_gettime(CLOCK_MONOTONIC, &bench_stamp) == -1)
			err(1, "clock_gettime");
		do_snap = 0;
	}

	if (qa.flags & QQ_BYPASS) {
		if (qa.flags &
		    (QQ_KPROBE|QQ_ENTRY_LEADER|QQ_MIN_AGG|QQ_THREAD_EVENTS) ||
		    graph_cache != NULL ||
		    maxnodes != -1 ||
		    lflag ||
		    filter_ppid ||
		    !do_snap)
			errx(1, "bypass(B) cannot be used with options: CegklmPs");
		qa.flags |= QQ_EBPF;
	}

	if ((qa.flags & QQ_ALL_BACKENDS) == 0)
		qa.flags |= QQ_ALL_BACKENDS;

	bzero(&sigact, sizeof(sigact));
	sigact.sa_flags = SA_RESTART | SA_RESETHAND;
	sigact.sa_handler = &sigint_handler;
	if (sigaction(SIGINT, &sigact, NULL) == -1)
		err(1, "sigaction");

	if (kube_config != NULL) {
		qa.kubefd = quark_start_kube_talker(kube_config,
		    &kube_talker_pid);
		if (qa.kubefd == -1)
			err(1, "can't start quark-kube-talker");
	}
	if ((qq = calloc(1, sizeof(*qq))) == NULL)
		err(1, "calloc");
	if (quark_queue_open(qq, &qa) != 0)
		err(1, "quark_queue_open");

	if (quark_verbose)
		fprintf(stderr, "using %s for backend\n", fetch_backend(qq));

	/* From now on we will be nobody */
	if (do_priv_drop)
		priv_drop();

	/*
	 * Debug mode, let the tree grow to >= maxnodes and bail, without
	 * popping nodes
	 */
	while (!gotsigint && maxnodes != -1 && qq->length < maxnodes) {
		quark_queue_populate(qq);
		quark_queue_block(qq);
	}

	/*
	 * Should we print all processes learned through scraping
	 */
	if (do_snap) {
		struct quark_process_iter	 qi;
		struct quark_event		 fake_ev;

		bzero(&fake_ev, sizeof(fake_ev));
		quark_process_iter_init(&qi, qq);

		while ((fake_ev.process = quark_process_iter_next(&qi)) != NULL)
			print_event(qq, &fake_ev);
	}

	/*
	 * Normal mode, collect, pop and dump elements until we get a sigint
	 */
	while (!gotsigint && maxnodes == -1) {
		qev = quark_queue_get_event(qq);

		/* No events, just block */
		if (qev == NULL) {
			if (quark_queue_block(qq) == -1 && errno != EINTR)
				err(1, "quark_queue_block");
			continue;
		}

		/*
		 * Benchmark mode, don't dump to stdout, just print stats every second
		 */
		if (benchmark) {
			if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
				err(1, "clock_gettime");

			if ((now.tv_sec - bench_stamp.tv_sec) >= 1) {
				dump_stats(qq);
				bench_stamp = now;
			}
			continue;
		}

		/*
		 * Filter out processes by parent pid if set
		 */
		if (filter_ppid &&
		    qev->process != NULL &&
		    (qev->process->flags & QUARK_F_PROC) &&
		    filter_ppid != qev->process->proc_ppid)
			continue;

		/*
		 * Finally print it to stdout
		 */
		print_event(qq, qev);
	}

	if (graph_by_pidtime != NULL && graph_by_time != NULL) {
		if (quark_dump_raw_event_graph(qq, graph_by_time,
		    graph_by_pidtime) == -1)
			warn("quark_dump_raw_event_graph");
		fclose(graph_by_time);
		fclose(graph_by_pidtime);
		graph_by_time = graph_by_pidtime = NULL;
	}
	if (graph_cache != NULL) {
		if (quark_dump_process_cache_graph(qq, graph_cache) == -1)
			warn("quark_dump_event_cache_graph");
		fclose(graph_cache);
		graph_cache = NULL;
	}

	dump_stats(qq);
	quark_queue_close(qq);
	if (qa.kubefd != -1)
		close(qa.kubefd);
	free(qq);

	return (0);
}
