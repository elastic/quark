// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "quark.h"

/* For bypass tests */
#include "elastic-ebpf/GPL/Events/EbpfEventProto.h"

#define MAN_QUARK_TEST
#include "manpages.h"

#define PATTERN "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

struct udphdr {
	u16 source;
	u16 dest;
	u16 len;
	u16 check;
};

#define msleep(_x)	usleep((uint64_t)_x * 1000ULL)

enum {
	SANE,
	RED,
	GREEN,
	YELLOW
};

static int	noforkflag;	/* don't fork on each test */
static int	bflag;		/* run bpf tests */
static int	kflag;		/* run kprobe tests */

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
	case YELLOW:
		printf("\033[33m");
		break;
	default:
		errx(1, "bad color %d", color);
	}

	old = color;

	return (ret);
}

static char *
binpath(const char *bin)
{
	static char	name[PATH_MAX];

	if (bin != NULL && realpath(bin, name) == NULL)
		err(1, "can't initialize binpath");
	else if (bin == NULL && name[0] == 0)
		err(1, "binpath not initialized");

	return (name);
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

static u32
sproc_self_namespace(const char *path)
{
	const char	*errstr;
	char		 buf[512], *start, *end;
	ssize_t		 n;
	u32		 v;
	int		 dfd;

	if ((dfd = open("/proc/self", O_PATH)) == -1)
		err(1, "open /proc/self");
	n = qreadlinkat(dfd, path, buf, sizeof(buf));
	close(dfd);
	if (n == -1)
		err(1, "qreadlinkat %s", path);
	else if (n >= (ssize_t)sizeof(buf))
		errx(1, "qreadlinkat %s truncation", path);
	if ((start = strchr(buf, '[')) == NULL)
		errx(1, "no [");
	if ((end = strchr(buf, ']')) == NULL)
		errx(1, "no ]");
	start++;
	*end = 0;

	v = strtonum(start, 0, UINT32_MAX, &errstr);
	if (errstr != NULL)
		errx(1, "strtonum %s: %s", start, errstr);

	return (v);
}

static int
num_open_fd(void)
{
	DIR		*dirp;
	struct dirent	*d;
	int		 n;

	if ((dirp = opendir("/proc/self/fd")) == NULL)
		err(1, "opendir");

	for (n = 0; (d = readdir(dirp)) != NULL;) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;
		n++;
	}
	/* Has to be at least one, since opendir does open */
	assert(n >= 1);
	closedir(dirp);

	/* Discount the FD from dirp */
	return (n - 1);
}

static void
dump_open_fd(FILE *f)
{
	int		 dfd;
	DIR		*dirp;
	struct dirent	*d;
	ssize_t		 n;
	char		 self[512], buf[512];

	if ((dfd = open("/proc/self/fd", O_DIRECTORY)) == -1)
		err(1, "open /proc/self/fd");
	if ((dirp = fdopendir(dfd)) == NULL)
		err(1, "fdopendir");

	snprintf(self, sizeof(self), "/proc/%d/fd", getpid());
	for (n = 0; (d = readdir(dirp)) != NULL;) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;
		n = qreadlinkat(dfd, d->d_name, buf, sizeof(buf));
		if (n == -1)
			err(1, "qreadlinkat");
		if (!strcmp(buf, self))
			continue;
		fprintf(f, "%s -> %s\n", d->d_name, buf);
	}

	closedir(dirp);		/* closes dfd */
	fflush(f);
}

struct test {
	char	 *name;
	int	(*func)(const struct test *, struct quark_queue_attr *);
	int	  backend;
	int	  excluded;
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
	fprintf(stderr, "usage: %s -h\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s [-1bkv] [-x test] [tests ...]\n",
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
		binpath(NULL),
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
		return (execv(binpath(NULL), argv));
	}

	/* parent */
	if (waitpid(child, &status, 0) == -1)
		err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		errx(1, "child didn't exit cleanly");

	return (child);
}

static int
clone_start(void *nada)
{
	_exit(0);

	/* NOTREACHED */
	return (0);
}

#define STACK_SIZE (1024UL * 128UL)

static pid_t
fork_clone_and_exit(void)
{
	int	 flags;
	u8	*stack, *stack_start;
	pid_t	 pid;

	/*
	 * First we do a normal fork, in this new process we will clone a new
	 * thread and call exit.
	 */
	if ((pid = fork()) == -1)
		err(1, "fork");
	/* parent just returns */
	if (pid != 0)
		return (pid);
	/* continue on child ... */

	/*
	 * Set up a stack, clone() is like fork and we just give it a stack
	 * without a starting addr.
	 */
	stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stack == MAP_FAILED)
		err(1, "mmap");
	stack_start = stack + STACK_SIZE;

	flags =
	    CLONE_VM |
	    CLONE_FS |
	    CLONE_FILES |
	    CLONE_SIGHAND |
	    CLONE_THREAD |
	    CLONE_SYSVSEM;

	/*
	 * clone the new thread, pid is tid
	 */
	pid = clone(clone_start, stack_start, flags, NULL);
	if (pid == -1)
		err(1, "clone3");

	/* Wait for the clone thread to exit */
	for (;;)
		sleep(1);

	/* NOTREACHED */
	if (munmap(stack, STACK_SIZE) == -1)
		err(1, "munmap");

	return 0;
}

#undef STACK_SIZE

static const struct quark_event *
drain_for_pid(struct quark_queue *qq, pid_t pid)
{
	const struct quark_event	*qev;
	struct timespec			 start, now;

	qev = NULL;
	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
		err(1, "clock_gettime");
	now = start;

	for (; ; (void)clock_gettime(CLOCK_MONOTONIC, &now)) {
		if ((now.tv_sec - start.tv_sec) >= 5) {
			errno = ETIME;
			err(1, "drain_for_pid");
		}

		qev = quark_queue_get_event(qq);

		if (qev == NULL) {
			if (quark_queue_block(qq) == -1)
				err(1, "quark_queue_block");
			continue;
		}

		if (pid == -1)
			break;
		if (qev->process == NULL)
			continue;
		if (qev->process->pid != (u32)pid)
			continue;
		break;
	}

	return (qev);
}

static void
assert_localhost(void)
{
	struct ifaddrs	*ifa;

	if (getifaddrs(&ifa) == -1)
		err(1, "getifaddrs");
	if (ifa == NULL)
		errx(1, "getifaddrs: no addresses");
	assert(!strcmp(ifa->ifa_name, "lo"));
	assert(ifa->ifa_addr != NULL);

	freeifaddrs(ifa);
}

static int
local_listen(u16 port, int type)
{
	struct sockaddr_in	sin;
	int			fd;

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = ntohs(port);
	if (inet_aton("127.0.0.1", &sin.sin_addr) != 1)
		errx(1, "inet_aton");
	if ((fd = socket(sin.sin_family, type, 0)) == -1)
		err(1, "socket");
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		err(1, "bind");
	if (type == SOCK_STREAM && listen(fd, 32) == -1)
		err(1, "listen");

	return (fd);
}

static int
local_connect(u16 port, int type, u16 *bound_port)
{
	struct sockaddr_in	sin;
	int			fd;

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = ntohs(port);
	if (inet_aton("127.0.0.1", &sin.sin_addr) != 1)
		errx(1, "inet_aton");
	if ((fd = socket(sin.sin_family, type, 0)) == -1)
		err(1, "socket");
	if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		err(1, "connect");
	if (bound_port != NULL) {
		socklen_t	socklen;

		socklen = sizeof(sin);
		if (getsockname(fd, (struct sockaddr *)&sin, &socklen) == -1)
			err(1, "getsockname");
		*bound_port = sin.sin_port;
	}

	return (fd);
}

static pid_t
fork_sock_write(u16 port, int type, u16 *bound_port)
{
	pid_t	child;
	int	status, listen_fd, conn_fd;
	ssize_t	n;
	int	pipefd[2];

	assert_localhost();

	/*
	 * We do the connect in the child, we use a pipe to send the bound port
	 * up to us.
	 */
	if (bound_port != NULL && pipe(pipefd) == -1)
		err(1, "pipe");

	if ((child = fork()) == -1) {
		err(1, "fork");
	} else if (child == 0) { /* child */
		listen_fd = local_listen(port, type);
		conn_fd = local_connect(port, type, bound_port);
		n = qwrite(conn_fd, PATTERN, strlen(PATTERN));
		if (n == -1)
			err(1, "qwrite");
		close(listen_fd);
		close(conn_fd);
		if (bound_port != NULL) {
			close(pipefd[0]);
			n = qwrite(pipefd[1], bound_port, sizeof(*bound_port));
			if (n == -1)
				err(1, "qwrite");
			close(pipefd[1]);
		}

		exit(0);
	}

	/* parent */
	if (waitpid(child, &status, 0) == -1)
		err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		errx(1, "child didn't exit cleanly");
	if (bound_port != NULL) {
		close(pipefd[1]);
		n = qread(pipefd[0], bound_port, sizeof(*bound_port));
		if (n == -1)
			err(1, "qread");
		else if (n == 0)
			err(1, "qread unexpected eof");
		else if (n != sizeof(*bound_port))
			errx(1, "qread short buf");
		close(pipefd[0]);
	}

	return (child);
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
	const struct quark_event	*qev;
	const struct quark_process	*qp;
	pid_t				 child;
	struct quark_cmdline_iter	 qcmdi;
	const char			*arg;
	size_t				 expected_args_len;
	int				 argc;
	char				 cwd[PATH_MAX];

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	child = fork_exec_nop();
	qev = drain_for_pid(&qq, child);

	/* check qev.events */
	assert(qev->events & QUARK_EV_FORK);
	assert(qev->events & QUARK_EV_EXEC);
	assert(qev->events & QUARK_EV_EXIT);
	/* check qev.process */
	qp = qev->process;
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
	/* XXX: assumes too much */
	/* Newer kernels default to 0x800000000 */
	assert(qp->proc_cap_inheritable == 0 ||
	    qp->proc_cap_inheritable == 0x800000000);
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
	assert(!strcmp(qp->filename, binpath(NULL)));
	/* check args */
	quark_cmdline_iter_init(&qcmdi, qp->cmdline, qp->cmdline_len);
	argc = 0;
	expected_args_len = 0;
	while ((arg = quark_cmdline_iter_next(&qcmdi)) != NULL) {
		/*
		 * Expected len is the length of the arguments summed up, plus one byte
		 * for each argument(the NUL after each argument, including the last
		 * one), so we just start at 'argc' bytes.
		 */
		expected_args_len += strlen(arg) + 1;

		switch (argc) {
		case 0:
			assert(!strcmp(arg, binpath(NULL)));
			break;
		case 1:
			assert(!strcmp(arg, "-N"));
			break;
		case 2:
			assert(!strcmp(arg, "this"));
			break;
		case 3:
			assert(!strcmp(arg, "is"));
			break;
		case 4:
			assert(!strcmp(arg, "nop!"));
			break;
		default:
			errx(1, "unexpected argc");
		}
		argc++;
	}
	assert(argc == 5);
	assert(qp->cmdline_len == expected_args_len);

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		err(1, "getcwd");
	assert(!strcmp(cwd, qp->cwd));

	quark_queue_close(&qq);

	return (0);
}

/* Make sure an exit comes from tgid, not tid */
static int
t_exit_tgid(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	pid_t				 pid;
	int				 i;

	/* More aggressive since we loop */
	qa->hold_time = 10;
	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	/*
	 * The actual tid is not reliable, sometimes an EBPF event would come
	 * with tid==tgid, so try it a few times
	 */
	for (i = 0; i < 20; i++) {
		pid = fork_clone_and_exit();
		qev = drain_for_pid(&qq, pid);
		assert(qev->process != NULL);
		assert(qev->events & QUARK_EV_FORK);
		assert(qev->events & QUARK_EV_EXIT);
	}

	quark_queue_close(&qq);

	return (0);
}

static int
t_bypass(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	struct timespec			 start, now;
	u64				 wanted;
	const struct ebpf_event_header	*eh;

	qa->flags &= ~QQ_ENTRY_LEADER;
	qa->flags |= QQ_BYPASS;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	(void)fork_exec_nop();
	wanted =
	    EBPF_EVENT_PROCESS_FORK |
	    EBPF_EVENT_PROCESS_EXEC |
	    EBPF_EVENT_PROCESS_EXIT;

	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
		err(1, "clock_gettime");
	for (now = start; wanted != 0; (void)clock_gettime(CLOCK_MONOTONIC, &now)) {
		if ((now.tv_sec - start.tv_sec) >= 5) {
			errno = ETIME;
			err(1, "bypass");
		}
		qev = drain_for_pid(&qq, -1);
		assert(qev->events == QUARK_EV_BYPASS);
		assert(qev->bypass != NULL);
		eh = qev->bypass;
		wanted &= ~eh->type;
	}

	quark_queue_close(&qq);

	return (0);
}

/* XXX Only probe loading for now */
static int
t_file(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;

	qa->flags &= ~QQ_ENTRY_LEADER;
	qa->flags |= QQ_BYPASS | QQ_FILE;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	quark_queue_close(&qq);

	return (0);
}

/* XXX Only probe loading for now */
static int
t_memfd(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;

	qa->flags &= ~QQ_ENTRY_LEADER;
	qa->flags |= QQ_BYPASS | QQ_MEMFD;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	quark_queue_close(&qq);

	return (0);
}

static int
t_sock_conn(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	pid_t				 child;
	u16				 bound_port;

	qa->flags |= QQ_SOCK_CONN;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	child = fork_sock_write(18888, SOCK_STREAM, &bound_port);

	/* QUARK_EV_FORK */
	qev = drain_for_pid(&qq, child);
	assert(qev->events == QUARK_EV_FORK);

	/* SOCK_CONN_ESTABLISHED */
	qev = drain_for_pid(&qq, child);
	assert(qev->events == QUARK_EV_SOCK_CONN_ESTABLISHED);
	assert(qev->process != NULL);
	assert((pid_t)qev->process->pid == child);
	assert(qev->socket != NULL);
	assert(qev->socket->established_time > 0);
	assert(qev->socket->from_scrape == 0);
	assert((pid_t)qev->socket->pid_origin == child);
	assert((pid_t)qev->socket->pid_last_use == child);
	assert(qev->socket->local.af == AF_INET);
	assert(qev->socket->local.addr4 == htonl(INADDR_LOOPBACK));
	assert(qev->socket->local.port == bound_port);
	assert(qev->socket->remote.af == AF_INET);
	assert(qev->socket->remote.addr4 == htonl(INADDR_LOOPBACK));
	assert(qev->socket->remote.port == htons(18888));
	assert(qev->socket->close_time == 0);

	/* SOCK_CONN_CLOSED */
	qev = drain_for_pid(&qq, child);
	assert(qev->events == QUARK_EV_SOCK_CONN_CLOSED);
	assert(qev->process != NULL);
	assert((pid_t)qev->process->pid == child);
	assert(qev->socket != NULL);
	assert(qev->socket->established_time > 0);
	assert(qev->socket->from_scrape == 0);
	assert((pid_t)qev->socket->pid_origin == child);
	assert((pid_t)qev->socket->pid_last_use == child);
	assert(qev->socket->local.af == AF_INET);
	assert(qev->socket->local.addr4 == htonl(INADDR_LOOPBACK));
	assert(qev->socket->local.port == bound_port);
	assert(qev->socket->remote.af == AF_INET);
	assert(qev->socket->remote.addr4 == htonl(INADDR_LOOPBACK));
	assert(qev->socket->remote.port == htons(18888));
	assert(qev->socket->close_time > 0);

	/* QUARK_EV_EXIT */
	qev = drain_for_pid(&qq, child);
	assert(qev->events == QUARK_EV_EXIT);

	quark_queue_close(&qq);

	return (0);
}

static int
t_namespace(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	pid_t				 child;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	child = fork_exec_nop();
	qev = drain_for_pid(&qq, child);

	assert(qev->process != NULL);
	assert(qev->process->proc_uts_inonum == sproc_self_namespace("ns/uts"));
	assert(qev->process->proc_ipc_inonum == sproc_self_namespace("ns/ipc"));
	assert(qev->process->proc_mnt_inonum == sproc_self_namespace("ns/mnt"));
	assert(qev->process->proc_net_inonum == sproc_self_namespace("ns/net"));

	quark_queue_close(&qq);

	return (0);
}

static int
t_cache_grace(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
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
	(void)drain_for_pid(&qq, child);
	/* Must be in cache now */
	qp = quark_process_lookup(&qq, child);
	assert(qp != NULL);
	assert((pid_t)qp->pid == child);
	/*
	 * Wait the configured cache_grace_time, run a dummy get_event to
	 * trigger the removal, ensure child is gone.
	 */
	msleep(qa->cache_grace_time);
	(void)quark_queue_get_event(&qq);

	assert(quark_process_lookup(&qq, child) == NULL);

	quark_queue_close(&qq);

	return (0);
}

static int
t_min_agg(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
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
	qev = drain_for_pid(&qq, child);
	assert(qev->events & QUARK_EV_FORK);
	assert(!(qev->events & (QUARK_EV_EXEC|QUARK_EV_EXIT)));
	qp = qev->process;
	assert(qp != NULL);
	assert((pid_t)qp->pid == child);
	assert(qp->flags & QUARK_F_PROC);
	/* Exec */
	qev = drain_for_pid(&qq, child);
	assert(qev->events & QUARK_EV_EXEC);
	assert(!(qev->events & (QUARK_EV_FORK|QUARK_EV_EXIT)));
	assert((pid_t)qp->pid == child);
	/* Exit */
	qev = drain_for_pid(&qq, child);
	assert(qev->events & QUARK_EV_EXIT);
	assert(!(qev->events & (QUARK_EV_FORK|QUARK_EV_EXEC)));
	qp = qev->process;
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
	(void)drain_for_pid(&qq, child);
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

static int
t_dns(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	struct quark_packet		*packet;
	pid_t				 child;
	struct iphdr			 ip;
	struct udphdr			 udp;
	u16				 bound_port;

	assert_localhost();

	qa->flags |= QQ_DNS;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	child = fork_sock_write(53, SOCK_DGRAM, &bound_port);

	/* first is the fork, no agg */
	qev = drain_for_pid(&qq, child);
	assert(qev->packet == NULL);

	/* egress */
	qev = drain_for_pid(&qq, child);
	packet = qev->packet;
	assert(packet != NULL);
	assert(packet->cap_len == 90);
	assert(packet->orig_len == 90);
	/* ip */
	memcpy(&ip, packet->data, sizeof(ip));
	assert(ip.protocol == IPPROTO_UDP);
	assert(ip.saddr == htonl(INADDR_LOOPBACK));
	assert(ip.daddr == htonl(INADDR_LOOPBACK));
	/* udp */
	memcpy(&udp, packet->data + sizeof(ip), sizeof(udp));
	assert(udp.dest == htons(53));
	assert(udp.source == bound_port);
	/* dns  */
	assert(!memcmp(packet->data + 28, PATTERN, packet->cap_len - 28));

	/* ingress */
	qev = drain_for_pid(&qq, child);
	packet = qev->packet;
	assert(packet != NULL);
	assert(packet->cap_len == 90);
	assert(packet->orig_len == 90);
	/* ip */
	memcpy(&ip, packet->data, sizeof(ip));
	assert(ip.protocol == IPPROTO_UDP);
	assert(ip.saddr == htonl(INADDR_LOOPBACK));
	assert(ip.daddr == htonl(INADDR_LOOPBACK));
	/* udp */
	memcpy(&udp, packet->data + sizeof(ip), sizeof(udp));
	assert(udp.dest == htons(53));
	assert(udp.source == bound_port);
	/* dns */
	assert(!memcmp(packet->data + 28, PATTERN, packet->cap_len - 28));

	quark_queue_close(&qq);

	return (0);
}

/*
 * Try to order by increasing order of complexity
 */
#define T(_x)		{ S(_x), _x, QQ_ALL_BACKENDS, 0 }
#define T_KPROBE(_x)	{ S(_x), _x, QQ_KPROBE, 0 }
#define T_EBPF(_x)	{ S(_x), _x, QQ_EBPF, 0 }
#define S(_x)		#_x
struct test all_tests[] = {
	T(t_probe),
	T(t_fork_exec_exit),
	T(t_exit_tgid),
	T_EBPF(t_bypass),
	T_EBPF(t_file),
	T_EBPF(t_memfd),
	T_EBPF(t_sock_conn),
	T_EBPF(t_dns),
	T(t_namespace),
	T(t_cache_grace),
	T(t_min_agg),
	T(t_stats),
	{ NULL,	NULL, 0, 0 }
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

static struct test *
lookup_test(const char *name)
{
	struct test	*t;

	for (t = all_tests; t->name != NULL; t++) {
		if (!strcmp(t->name, name))
			return (t);
	}

	return (NULL);
}

static int
run_test_doit(struct test *t, struct quark_queue_attr *qa)
{
	int			r, before_nfd, after_nfd;;
	struct quark_queue_attr qa_copy;

	/*
	 * Check for FD leaks
	 */
	before_nfd = num_open_fd();
	qa_copy = *qa;
	r = t->func(t, &qa_copy);
	after_nfd = num_open_fd();
	if (before_nfd != after_nfd) {
		fprintf(stderr,
		    "FDLEAK DETECTED! %d opened descriptors, expected %d\n",
		    after_nfd, before_nfd);
		dump_open_fd(stderr);
		if (r == 0)
			r = 1;
	}

	return (r);
}
/*
 * A test runs as a subprocess to avoid contamination.
 */
static int
run_test(struct test *t, struct quark_queue_attr *qa)
{
	pid_t		 child;
	int		 status, x, linepos, be, r;
	int		 child_stderr[2];
	FILE		*child_stream;
	char		*child_buf;
	size_t		 child_buflen;
	ssize_t		 n;

	/*
	 * Figure out if this is ebpf or kprobe
	 */
	be = backend_of_attr(qa);
	if (be != QQ_EBPF && be != QQ_KPROBE)
		errx(1, "bad backend");

	linepos = printf("%s @ %s", t->name,
	    be == QQ_EBPF ? "ebpf" : "kprobe");
	while (++linepos < 30)
		putchar('.');

	fflush(stdout);

	if (((t->backend & be) == 0) || t->excluded) {
		x = color(YELLOW);
		printf("n/a\n");
		color(x);
		fflush(stdout);

		return (0);
	}

	if (noforkflag) {
		r = run_test_doit(t, qa);
		if (r == 0) {
			x = color(GREEN);
			printf("ok\n");
			color(x);
		} else {
			x = color(RED);
			printf("failed\n");
			color(x);
		}
		fflush(stdout);

		return (r);
	}

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

		exit(run_test_doit(t, qa));
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

		n = qread(child_stderr[0], buf, sizeof(buf));
		if (n == -1)
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
	if (WIFSIGNALED(status))
		fprintf(stderr, "exited with signal %d (%s)\n",
		    WTERMSIG(status), strsignal(WTERMSIG(status)));
	else if (WCOREDUMP(status))
		fprintf(stderr, "core dumped\n");

	/*
	 * Children exited, close the stream and print it out.
	 */
	fclose(child_stream);
	n = qwrite(STDERR_FILENO, child_buf, child_buflen);
	if (n == -1)
		err(1, "qwrite");
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
	struct test		*t;
	int			 failed, i;
	struct quark_queue_attr	 bpf_attr;
	struct quark_queue_attr	 kprobe_attr;

	quark_queue_default_attr(&bpf_attr);
	bpf_attr.flags &= ~QQ_ALL_BACKENDS;
	bpf_attr.flags |= QQ_EBPF | QQ_ENTRY_LEADER;
	bpf_attr.hold_time = 100;

	quark_queue_default_attr(&kprobe_attr);
	kprobe_attr.flags &= ~QQ_ALL_BACKENDS;
	kprobe_attr.flags |= QQ_KPROBE | QQ_ENTRY_LEADER;
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
				errx(1, "test %s doesn't exist", argv[i]);
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
	int		  ch, failed, x;
	struct test	 *t;

	binpath(argv[0]);

	while ((ch = getopt(argc, argv, "1bhklNvVx:")) != -1) {
		switch (ch) {
		case '1':
			noforkflag = 1;
			break;
		case 'b':
			bflag = 1;
			break;
		case 'h':
			if (isatty(STDOUT_FILENO))
				display_man();
			else
				usage();
			break;	/* NOTREACHED */
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
		case 'x':
			if ((t = lookup_test(optarg)) == NULL)
				errx(1, "test %s doesn't exist", optarg);
			t->excluded = 1;
			break;
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
