// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/wait.h>

#include "quark.h"

static int	bflag;	/* run bpf tests */
static int	kflag;	/* run kprobe tests */

#define msleep(_x)	usleep((uint64_t)_x * 1000ULL)

enum {
	SANE,
	RED,
	GREEN
};

static int
fancy_tty(void)
{
	char	*term = getenv("TERM");

	if (term == NULL || !strcmp(term, "dumb"))
		return (0);

	return (isatty(STDOUT_FILENO) == 1);
}

static int
color(int color)
{
	static int	 old;
	int		 ret;

	if (!fancy_tty())
		return (SANE);

	ret = old;

	switch (color) {
	case SANE:
		printf("\033[0m");
		break;
	case RED:
		printf("\033[31m");
		break;
	case GREEN:
		printf("\033[32m");
		break;
	default:
		errx(1, "bad color %d", color);
	}

	old = color;

	return (ret);
}

static char *
binpath(void)
{
	static char	name[PATH_MAX];

	if (readlink("/proc/self/exe", name, sizeof(name)) == -1)
		err(1, "readlink");

	return name;
}

static int
backend_of_attr(struct quark_queue_attr *qa)
{
	int	be;

	if (((qa->flags & QQ_ALL_BACKENDS) == QQ_ALL_BACKENDS))
		errx(1, "backend must be explicit");
	else if (qa->flags & QQ_EBPF)
		be = QQ_EBPF;
	else if (qa->flags & QQ_KPROBE)
		be = QQ_KPROBE;
	else
		errx(1, "bad flags");

	return (be);
}

static void
spin(void)
{
	static int ch;

	if (!fancy_tty())
		return;

	/* -\|/ */
	switch (ch) {
	case 0:			/* FALLTHROUGH */
	case '-':
		ch = '\\';
		break;
	case '\\':
		ch = '|';
		break;
	case '|':
		ch = '/';
		break;
	case '/':
		ch = '-';
		break;
	default:
		ch = '?';
	}

	printf("%c\b", ch);
	fflush(stdout);
}

struct test {
	char	 *name;
	int	(*func)(const struct test *, struct quark_queue_attr *);
};

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
	fprintf(stderr, "usage: %s [-bkv] [tests ...]\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s -l\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s -N\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s -V\n",
	    program_invocation_short_name);

	exit(1);
}

static pid_t
fork_exec_nop(void)
{
	pid_t		child;
	int		status;
	char *const	argv[] = {
		binpath(),
		"-N",
		"this",
		"is",
		"nop!",
		NULL
	};

	if ((child = fork()) == -1)
		err(1, "fork");
	else if (child == 0) {
		/* child */
		return (execv(binpath(), argv));
	}

	/* parent */
	if (waitpid(child, &status, 0) == -1)
		err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		errx(1, "child didn't exit cleanly");

	return (child);
}

static int
drain_for_pid(struct quark_queue *qq, pid_t pid, struct quark_event *qev)
{
	int			n;

	for (;;) {
		n = quark_queue_get_events(qq, qev, 1);
		if (n == -1) {
			err(1, "quark_queue_get_events");
		} else if (n == 0) {
			if (quark_queue_block(qq) == -1)
				err(1, "quark_queue_block");
			continue;
		} else if (n != 1)
			errx(1, "quark_queue_get_events is broken");

		if (qev->process == NULL)
			continue;
		if (qev->process->pid != (u32)pid)
			continue;
		break;
	}

	return (0);
}

static int
t_probe(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue	qq;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "%s: quark_queue_open", t->name);
	quark_queue_close(&qq);

	return (0);
}

static int
t_fork_exec_exit(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	struct quark_event		 qev;
	const struct quark_process	*qp;
	pid_t				 child;
	struct args			*args;
	size_t				 expected_len;
	int				 i;
	char				 cwd[PATH_MAX];

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	child = fork_exec_nop();
	if (drain_for_pid(&qq, child, &qev) != 0)
		err(1, "drain_for_pid");

	/* check qev.events */
	assert(qev.events & QUARK_EV_FORK);
	assert(qev.events & QUARK_EV_EXEC);
	assert(qev.events & QUARK_EV_EXIT);
	/* check qev.process */
	qp = qev.process;
	assert(qp != NULL);
	assert(qp->flags & QUARK_F_EXIT);
	assert(qp->flags & QUARK_F_COMM);
	assert(qp->flags & QUARK_F_FILENAME);
	assert(qp->flags & QUARK_F_CMDLINE);
	assert(qp->flags & QUARK_F_CWD);
	assert((pid_t)qp->pid == child);
	assert((pid_t)qp->proc_ppid == getpid());
	assert(qp->proc_time_boot > 0); /* XXX: improve */
	assert(qp->proc_uid == getuid());
	assert(qp->proc_gid == getgid());
	assert(qp->proc_suid == geteuid());
	assert(qp->proc_sgid == getegid());
	assert(qp->proc_euid == geteuid());
	assert(qp->proc_egid == getegid());
	assert((pid_t)qp->proc_pgid == getpgid(0));
	assert((pid_t)qp->proc_sid == getsid(0));
	/* check capabilities */
	/* XXX assumes we're root */
	assert(qp->proc_cap_inheritable == 0);
	/*
	 * We don't know the exact set since it varies from kernel,
	 * improve this in the future.
	 */
	assert(qp->proc_cap_effective != 0);
	assert(qp->proc_cap_permitted != 0);
	/* check entry leader */
	/*
	 * XXX TODO This depends how we're running the test, if we're over ssh
	 * it will show ssh, if not it will show init and whatnot, for now
	 * assert that it is not unknown at least.
	 */
	assert(qp->proc_entry_leader != 0);
	assert(qp->proc_entry_leader_type != QUARK_ELT_UNKNOWN);
	/* XXX TODO check tty_major and tty_minor for self in the future */
#if 0
	assert(qp->proc_tty_major != QUARK_TTY_UNKNOWN);
	assert(qp->proc_tty_minor != 0);
#endif
	/* check strings */
	assert(!strcmp(qp->comm, program_invocation_short_name));
	assert(!strcmp(qp->filename, binpath()));
	/* check args */
	args = args_make(qp);
	assert(args != NULL);
	assert(args->argc == 5);
	assert(!strcmp(args->argv[0], binpath()));
	assert(!strcmp(args->argv[1], "-N"));
	assert(!strcmp(args->argv[2], "this"));
	assert(!strcmp(args->argv[3], "is"));
	assert(!strcmp(args->argv[4], "nop!"));
	/*
	 * Expected len is the length of the arguments summed up, plus one byte
	 * for each argument(the NUL after each argument, including the last
	 * one), so we just start at 'argc' bytes.
	 */
	for (expected_len = args->argc, i = 0; i < args->argc; i++)
		expected_len += strlen(args->argv[i]);
	args_free(args);
	assert(qp->cmdline_len == expected_len);

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		err(1, "getcwd");
	assert(!strcmp(cwd, qp->cwd));

	quark_queue_close(&qq);

	return (0);
}

static int
t_cache_grace(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	struct quark_event		 qev;
	const struct quark_process	*qp;
	pid_t				 child;

	/*
	 * Default grace time would slow down this test too much
	 */
	qa->cache_grace_time = 100;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	/*
	 * Check that we ourselves exist before getting events, meaning we came
	 * from /proc scraping
	 */
	qp = quark_process_lookup(&qq, getpid());
	assert(qp != NULL);
	assert((pid_t)qp->pid == getpid());

	/*
	 * Fork a child, drain until we see it.
	 */
	child = fork_exec_nop();
	if (drain_for_pid(&qq, child, &qev) != 0)
		err(1, "drain_for_pid");
	/* Must be in cache now */
	qp = quark_process_lookup(&qq, child);
	assert(qp != NULL);
	assert((pid_t)qp->pid == child);
	/*
	 * Wait the configured cache_grace_time, run a dummy get_event to
	 * trigger the removal, ensure child is gone.
	 */
	msleep(qa->cache_grace_time);
	if (quark_queue_get_events(&qq, &qev, 1) == -1)
		err(1, "quark_queue_get_events");

	assert(quark_process_lookup(&qq, child) == NULL);

	quark_queue_close(&qq);

	return (0);
}

static int
t_min_agg(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	struct quark_event		 qev;
	const struct quark_process	*qp;
	pid_t				 child;

	qa->flags |= QQ_MIN_AGG;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	/*
	 * Fork a child, since there is no aggregation, we should see 3 events
	 * for the same pid: FORK + EXEC + EXIT.
	 */
	child = fork_exec_nop();

	/* Fork */
	if (drain_for_pid(&qq, child, &qev) != 0)
		err(1, "drain_for_pid fork");
	assert(qev.events & QUARK_EV_FORK);
	assert(!(qev.events & (QUARK_EV_EXEC|QUARK_EV_EXIT)));
	qp = qev.process;
	assert(qp != NULL);
	assert((pid_t)qp->pid == child);
	assert(qp->flags & QUARK_F_PROC);
	/* Exec */
	if (drain_for_pid(&qq, child, &qev) != 0)
		err(1, "drain_for_pid exec");
	assert(qev.events & QUARK_EV_EXEC);
	assert(!(qev.events & (QUARK_EV_FORK|QUARK_EV_EXIT)));
	assert((pid_t)qp->pid == child);
	/* Exit */
	if (drain_for_pid(&qq, child, &qev) != 0)
		err(1, "drain_for_pid exit");
	assert(qev.events & QUARK_EV_EXIT);
	assert(!(qev.events & (QUARK_EV_FORK|QUARK_EV_EXEC)));
	qp = qev.process;
	assert(qp != NULL);
	assert((pid_t)qp->pid == child);
	assert(qp->flags & QUARK_F_EXIT);
	assert(qp->exit_code == 0);
	assert(qp->exit_time_event > 0);

	quark_queue_close(&qq);

	return (0);
}

static int
t_stats(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	struct quark_event		 qev;
	pid_t				 child;
	struct quark_queue_stats	 old_stats, stats;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	quark_queue_get_stats(&qq, &old_stats);
	assert(old_stats.backend == backend_of_attr(qa));
	assert(old_stats.insertions == 0);
	assert(old_stats.removals == 0);
	assert(old_stats.aggregations == 0);
	assert(old_stats.non_aggregations == 0);
	assert(old_stats.lost == 0);
	/*
	 * Fork a child, drain until we see it.
	 */
	child = fork_exec_nop();
	if (drain_for_pid(&qq, child, &qev) != 0)
		err(1, "drain_for_pid");
	/*
	 * Stats must have bumped now
	 */
	quark_queue_get_stats(&qq, &stats);
	assert(stats.backend == old_stats.backend);
	assert(stats.insertions > old_stats.insertions);
	assert(stats.removals > old_stats.removals);
	assert(stats.aggregations > old_stats.aggregations);
	/* Can't state anything about non_aggregations */
	/* If we're losing here, all hope is lost */
	assert(old_stats.lost == 0);
	/* XXX We should trigger lost events and ensure here XXX */

	quark_queue_close(&qq);

	return (0);
}

/*
 * Try to order by increasing order of complexity
 */
#define T(_x) { S(_x),	_x }
#define S(_x) #_x
const struct test all_tests[] = {
	T(t_probe),
	T(t_fork_exec_exit),
	T(t_cache_grace),
	T(t_min_agg),
	T(t_stats),
	{ NULL,	NULL }
};
#undef S
#undef T

static void
display_tests(void)
{
	const struct test	*t;

	for (t = all_tests; t->name != NULL; t++)
		printf("%s\n", t->name);

	exit(0);
}

static const struct test *
lookup_test(const char *name)
{
	const struct test	*t;

	for (t = all_tests; t->name != NULL; t++) {
		if (!strcmp(t->name, name))
			return (t);
	}

	return (NULL);
}

/*
 * A test runs as a subprocess to avoid contamination.
 */
static int
run_test(const struct test *t, struct quark_queue_attr *qa)
{
	pid_t		 child;
	int		 status, x, linepos;
	const char	*be;
	int		 child_stderr[2];
	FILE		*child_stream;
	char		*child_buf;
	size_t		 child_buflen;
	ssize_t		 n;

	/*
	 * Figure out if this is ebpf or kprobe
	 */
	if (backend_of_attr(qa) == QQ_EBPF)
		be = "ebpf";
	else if (backend_of_attr(qa) == QQ_KPROBE)
		be = "kprobe";
	else
		errx(1, "bad backend");

	linepos = printf("%s @ %s", t->name, be);
	while (++linepos < 30)
		putchar('.');
	fflush(stdout);

	/*
	 * Create a pipe to save the child stderr, so we don't get crappy
	 * interleaved output with the parent.
	 */
	if (pipe(child_stderr) == -1)
		err(1, "pipe");

	/*
	 * Fork child and point its stderr to the pipe
	 */
	if ((child = fork()) == -1)
		err(1, "fork");
	else if (child == 0) {
		dup2(child_stderr[1], STDERR_FILENO);
		close(child_stderr[1]);
		close(child_stderr[0]);
		exit(t->func(t, qa));
	}
	close(child_stderr[1]);

	/*
	 * Open a write stream to save child's stderr output
	 */
	child_buf = NULL;
	child_buflen = 0;
	child_stream = open_memstream(&child_buf, &child_buflen);
	if (child_stream == NULL)
		err(1, "open_memstream");

	/*
	 * Drain the pipe until EOF, meaning the child exited
	 */
	for (;;) {
		fd_set		rfds;
		struct timeval	tv;
		int		r;
		char		buf[4096];

		spin();
		tv.tv_sec = 0;
		tv.tv_usec = 25;

		FD_ZERO(&rfds);
		FD_SET(child_stderr[0], &rfds);

		r = select(child_stderr[0] + 1, &rfds, NULL, NULL, &tv);
		if (r == -1 && (errno == EINTR))
			continue;
		else if (r == -1)
			err(1, "select");
		else if (r == 0)
			continue;
		if (!FD_ISSET(child_stderr[0], &rfds))
			errx(1, "rfds should be set");

	read_again:
		n = read(child_stderr[0], buf, sizeof(buf));
		if (n == -1 && errno == EINTR)
			goto read_again;
		else if (n == -1)
			err(1, "read");
		else if (n == 0) {
			close(child_stderr[0]);
			break;
		}
		/* n is positive, move to the stream */
		if (fwrite(buf, 1, n, child_stream) != (size_t)n)
			err(1, "fwrite");
		if (ferror(child_stream))
			err(1, "fwrite");
		if (feof(child_stream))
			errx(1, "fwrite got EOF");
	}

	/*
	 * We only get here when we get an EOF from the child pipe, so it
	 * must have exited.
	 */
	if (waitpid(child, &status, 0) == -1)
		err(1, "waitpid");

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		x = color(GREEN);
		printf("ok\n");
		color(x);
	} else {
		x = color(RED);
		printf("failed\n");
		color(x);
	}
	fflush(stdout);

	/*
	 * Children exited, close the stream and print it out.
	 */
	fclose(child_stream);
write_again:
	n = write(STDERR_FILENO, child_buf, child_buflen);
	if (n == -1 && errno == EINTR)
		goto write_again;
	else if (n == -1)
		err(1, "write");
	else if (n != (ssize_t)child_buflen)
		errx(1, "write shortcount");
	free(child_buf);
	child_buf = NULL;
	child_buflen = 0;

	if (WIFEXITED(status))
		return (WEXITSTATUS(status));

	return (-1);
}

static int
run_tests(int argc, char *argv[])
{
	const struct test	*t;
	int			 failed, i;
	struct quark_queue_attr	 bpf_attr;
	struct quark_queue_attr	 kprobe_attr;

	quark_queue_default_attr(&bpf_attr);
	bpf_attr.flags &= ~QQ_ALL_BACKENDS;
	bpf_attr.flags |= QQ_EBPF | QQ_NO_SNAPSHOT | QQ_ENTRY_LEADER;
	bpf_attr.hold_time = 100;

	quark_queue_default_attr(&kprobe_attr);
	kprobe_attr.flags &= ~QQ_ALL_BACKENDS;
	kprobe_attr.flags |= QQ_KPROBE | QQ_NO_SNAPSHOT | QQ_ENTRY_LEADER;
	kprobe_attr.hold_time = 100;

	failed = 0;
	if (argc == 0) {
		for (t = all_tests; t->name != NULL; t++) {
			if (bflag && run_test(t, &bpf_attr) != 0)
				failed++;
			if (kflag && run_test(t, &kprobe_attr) != 0)
				failed++;
		}
	} else {
		for (i = 0; i < argc; i++) {
			t = lookup_test(argv[i]);
			if (t == NULL)
				errx(1, "test %s not found", argv[i]);
			if (bflag && run_test(t, &bpf_attr) != 0)
				failed++;
			if (kflag && run_test(t, &kprobe_attr) != 0)
				failed++;
		}
	}

	return (failed);
}

int
main(int argc, char *argv[])
{
	int	ch, x, failed;

	while ((ch = getopt(argc, argv, "bklNvV")) != -1) {
		switch (ch) {
		case 'b':
			bflag = 1;
			break;
		case 'k':
			kflag = 1;
			break;
		case 'l':
			display_tests();
			break;	/* NOTREACHED */
		case 'N':
			exit(0);
			break;	/* NOTREACHED */
		case 'v':
			quark_verbose++;
			break;
		case 'V':
			display_version();
			break;	/* NOTREACHED */
		default:
			usage();
		}
	}

	if (!bflag && !kflag)
		bflag = kflag = 1;

	argc -= optind;
	argv += optind;

	failed = run_tests(argc, argv);

	x = failed == 0 ? color(GREEN) : color(RED);
	printf("%d failures\n", failed);
	color(x);

	return (failed);
}