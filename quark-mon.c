#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "quark.h"

static int gotsigint;

static void
quark_queue_dump_stats(struct quark_queue *qq)
{
	struct quark_queue_stats *s = &qq->stats;
	printf("%8llu insertions %8llu removals %8llu aggregations %8llu non-aggregations\n",
	    s->insertions, s->removals, s->aggregations, s->non_aggregations);
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
	int				 ch, maxnodes;
	int				 dump_perf, qq_flags;
	int				 do_drop;
	struct quark_queue		*qq;
	struct raw_event		*raw;
	struct sigaction		 sigact;
	FILE				*graph_by_time, *graph_by_pidtime;

	maxnodes = -1;
	qq_flags = dump_perf = do_drop = 0;

	while ((ch = getopt(argc, argv, "Dfm:tv")) != -1) {
		const char *errstr;

		switch (ch) {
		case 'D':
			do_drop = 1;
			break;
		case 'f':
			qq_flags |= QQ_PERF_TASK_EVENTS;
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

	if (quark_init() == -1)
		errx(1, "quark_init");
	if ((qq = calloc(1, sizeof(*qq))) == NULL)
		err(1, "calloc");
	if (quark_queue_open(qq, qq_flags) != 0)
		errx(1, "quark_queue_open");
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
		raw = quark_queue_pop(qq);
		if (raw == NULL) {
			quark_queue_block(qq);
			continue;
		}
		raw_event_dump(raw, 0); /* userlike function */
		raw_event_free(raw);
	}

	quark_dump_graphviz(qq, graph_by_time, graph_by_pidtime);
	fclose(graph_by_time);
	fclose(graph_by_pidtime);

	quark_queue_dump_stats(qq);
	quark_queue_close(qq);
	free(qq);
	if (!do_drop)
		quark_close();

	return (0);
}
