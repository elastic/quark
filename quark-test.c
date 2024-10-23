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

#include <sys/wait.h>

#include "quark.h"

#define msleep(_x) usleep((uint64_t)_x * 1000ULL)

static void
spin(void)
{
	static int ch;
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

struct quark_queue_attr bpf_attr;
struct quark_queue_attr kprobe_attr;

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
	fprintf(stderr, "usage: %s [-v]",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s -N [nop args..]\n", program_invocation_short_name);
	fprintf(stderr, "usage: %s -V\n", program_invocation_short_name);

	exit(1);
}

static pid_t
fork_exec_nop(void)
{
	pid_t		child;
	int		status;
	char *const	argv[] = {
		"/proc/self/exe",
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
		return (execv("/proc/self/exe", argv));
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
	char				 cwd[PATH_MAX];

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "%s: quark_queue_open", t->name);

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
	 * it will show ssh, if not it will show init and whatnot, for assert
	 * that it is not unknown at least.
	 */
	assert(qp->proc_entry_leader != 0);
	assert(qp->proc_entry_leader_type != QUARK_ELT_UNKNOWN);
	/* XXX TODO check tty_major and tty_minor for self in the future */
#if 0
	assert(qp->proc_tty_major != QUARK_TTY_UNKNOWN);
	assert(qp->proc_tty_minor != 0);
#endif
	/* check strings */
	assert(!strcmp(qp->comm, "exe"));
	assert(!strcmp(qp->filename, "/proc/self/exe"));
	/* check args */
	args = args_make(qp);
	assert(args != NULL);
	assert(args->argc == 5);
	assert(!strcmp(args->argv[0], "/proc/self/exe"));
	assert(!strcmp(args->argv[1], "-N"));
	assert(!strcmp(args->argv[2], "this"));
	assert(!strcmp(args->argv[3], "is"));
	assert(!strcmp(args->argv[4], "nop!"));
	args_free(args);
	assert(qp->cmdline_len == 31);
	if (getcwd(cwd, sizeof(cwd)) == NULL)
		err(1, "getcwd");
	assert(!strcmp(cwd, qp->cwd));

	quark_queue_close(&qq);

	return (0);
}

#define S(_x) #_x
const struct test all_tests[] = {
	{ S(t_probe),		t_probe},
	{ S(t_fork_exec_exit),	t_fork_exec_exit},
	{ NULL,			NULL}
};
#undef S


/*
 * A test runs as a subprocess to avoid contamination.
 */
static int
run_test(const struct test *t, struct quark_queue_attr *qa)
{
	pid_t		 child;
	int		 status;
	const char	*be;

	if (((qa->flags & QQ_ALL_BACKENDS) == QQ_ALL_BACKENDS))
		errx(1, "backend must be explicit");
	if (qa->flags & QQ_EBPF)
		be = "ebpf";
	else if (qa->flags & QQ_KPROBE)
		be = "kprobe";
	else
		errx(1, "bad flags");

	printf("%s @ %s: ", t->name, be);
	fflush(stdout);

	if ((child = fork()) == -1)
		err(1, "fork");
	else if (child == 0)
		exit(t->func(t, qa));

	for (;;) {
		pid_t	r;

		r = waitpid(child, &status, WNOHANG);
		if (r == -1)
			err(1, "waitpid");
		else if (r == 0) {
			spin();
			msleep(25);
			continue;
		} else
			break;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		printf("ok\n");
	else
		printf("failed\n");

	if (WIFEXITED(status))
		return (WEXITSTATUS(status));

	return (-1);
}

int
main(int argc, char *argv[])
{
	const struct test	*t;
	int			 failed, ch;

	while ((ch = getopt(argc, argv, "NvV")) != -1) {
		switch (ch) {
		case 'N':
			exit(0);
			break;	/* NOTREACHED */
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

	quark_queue_default_attr(&bpf_attr);
	bpf_attr.flags &= ~QQ_ALL_BACKENDS;
	bpf_attr.flags |= QQ_EBPF | QQ_NO_SNAPSHOT | QQ_ENTRY_LEADER;
	bpf_attr.hold_time = 100;

	quark_queue_default_attr(&kprobe_attr);
	kprobe_attr.flags &= ~QQ_ALL_BACKENDS;
	kprobe_attr.flags |= QQ_KPROBE | QQ_NO_SNAPSHOT | QQ_ENTRY_LEADER;
	kprobe_attr.hold_time = 100;

	failed = 0;
	for (t = all_tests; t->name != NULL; t++) {
		if (run_test(t, &bpf_attr) != 0)
			failed++;
		if (run_test(t, &kprobe_attr) != 0)
			failed++;
	}

	printf("failed tests %d\n", failed);

	return (failed);
}
