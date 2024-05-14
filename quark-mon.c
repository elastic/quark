#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "quark.h"

static int gotsigint;

static void
quark_queue_dump_stats(struct quark_queue *qq)
{
	struct quark_queue_stats s;

	quark_queue_get_stats(qq, &s);
	printf("%8llu insertions %8llu removals %8llu aggregations "
	    "%8llu non-aggregations %8llu lost\n",
	    s.insertions, s.removals, s.aggregations,
	    s.non_aggregations, s.lost);
}

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

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-Dfptv] [-m max_nodes]\n",
	    program_invocation_short_name);

	exit(1);
}

int
main(int argc, char *argv[])
{
	int				 ch, maxnodes, n, i;
	int				 dump_perf, qq_flags;
	int				 do_drop, nqevs;
	struct quark_queue		*qq;
	struct quark_event		*qev, *qevs;
	struct sigaction		 sigact;
	FILE				*graph_by_time, *graph_by_pidtime;

	maxnodes = -1;
	qq_flags = dump_perf = do_drop = 0;
	nqevs = 32;

	while ((ch = getopt(argc, argv, "bDkm:tv")) != -1) {
		const char *errstr;

		switch (ch) {
		case 'b':
			qq_flags |= QQ_EBPF;
			break;
		case 'D':
			do_drop = 1;
			break;
		case 'k':
			qq_flags |= QQ_KPROBE;
			break;
		case 'm':
			maxnodes = strtonum(optarg, 1, 2000000, &errstr);
			if (errstr != NULL)
				errx(1, "invalid maxnodes: %s", errstr);
			break;
		case 't':
			qq_flags |= QQ_THREAD_EVENTS;
			break;
		case 'v':
			quark_verbose++;
			break;
		default:
			usage();
		}
	}

	bzero(&sigact, sizeof(sigact));
	sigact.sa_flags = SA_RESTART | SA_RESETHAND;
	sigact.sa_handler = &sigint_handler;
	if (sigaction(SIGINT, &sigact, NULL) == -1)
		err(1, "sigaction");

	if ((qq = calloc(1, sizeof(*qq))) == NULL)
		err(1, "calloc");
	if (quark_queue_open(qq, qq_flags) != 0)
		errx(1, "quark_queue_open");
	if ((qevs = calloc(nqevs, sizeof(*qevs))) == NULL)
		err(1, "calloc");
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

	/*
	 * Debug mode, let the tree grow to >= maxnodes and bail, without
	 * popping nodes
	 */
	while (!gotsigint && maxnodes != -1 && qq->length < maxnodes) {
		quark_queue_populate(qq);
		quark_queue_block(qq);
	}

	/*
	 * Normal mode, collect, pop and dump elements until we get a sigint
	 */
	while (!gotsigint && maxnodes == -1) {
		n = quark_queue_get_events(qq, qevs, nqevs);
		if (n == -1)
			err(1, "quark_queue_get_events");
		/* Scan each event */
		for (i = 0, qev = qevs; i < n; i++, qev++)
			quark_event_dump(qev, stdout);
		/* No events, just block */
		if (n == 0) {
			quark_queue_block(qq);
			continue;
		}
	}

	quark_dump_graphviz(qq, graph_by_time, graph_by_pidtime);
	fclose(graph_by_time);
	fclose(graph_by_pidtime);

	free(qevs);
	quark_queue_dump_stats(qq);
	quark_queue_close(qq);
	free(qq);

	return (0);
}
