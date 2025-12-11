// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <asm/termbits.h>

#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include <stdarg.h>
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

#define PATTERN		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
#define STATUS_LINELEN	32
#define MAXTESTS	512

struct udphdr {
	u16 source;
	u16 dest;
	u16 len;
	u16 check;
};

struct progress {
	int green;
	int red;
	int total;
	int state[MAXTESTS];
};

struct test {
	char	 *name;
	int	(*func)(const struct test *, struct quark_queue_attr *);
	int	  backend;
	int	  excluded;
};

#define msleep(_x)	usleep((uint64_t)_x * 1000ULL)
#define TS_TO_NS(_ts)	(((_ts)->tv_sec * NS_PER_S) + (_ts)->tv_nsec)

enum {
	SANE,
	RED,
	GREEN,
	YELLOW
};

static int	noforkflag;	/* don't fork on each test */
static int	bflag;		/* run bpf tests */
static int	kflag;		/* run kprobe tests */
static u64	boottime;
static int	fancy_tty;
static int	in_valgrind;

static int
probe_fancy_tty(void)
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

	if (!fancy_tty)
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

static int
backend_of_attr(struct quark_queue_attr *qa)
{
	int	be;

	if (qa == NULL)
		return (-1);
	else if (((qa->flags & QQ_ALL_BACKENDS) == QQ_ALL_BACKENDS))
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

	if (!fancy_tty || in_valgrind)
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

#define erase_from_cursor()	printf("\033[0K")
#define cursor_up(_n)		printf("\033[%dA", _n)

static void
progress_add(struct progress *progress, int state)
{
	int	idx;

	idx = progress->green + progress->red;
	if (idx == MAXTESTS)
		err(1, "max tests reached! bump MAXTESTS!");
	if (state == GREEN)
		progress->green++;
	else if (state == RED)
		progress->red++;
	else
		err(1, "bad progress state");
	progress->state[idx] = state;
}

static void
progress_print(struct progress *progress)
{
	int	i, x, finished;

	if (!fancy_tty || progress->total == 1)
		return;

	finished = progress->green + progress->red;

	erase_from_cursor();
	putchar('\n');
	if (finished != progress->total) {
		erase_from_cursor();
		putchar('\n');
	}
	putchar('[');
	for (i = 0; i < finished; i++) {
		x = color(progress->state[i]);
		putchar('#');
		color(x);
	}
	for (i = 0; i < (progress->total - finished); i++)
		putchar(' ');
	putchar(']');
	putchar(' ');
	x = color(GREEN);
	printf("%d", progress->green);
	color(x);
	putchar('/');
	x = color(RED);
	printf("%d", progress->red);
	color(x);
	putchar('/');
	printf("%d", progress->total);

	if (finished == progress->total)
		putchar('\n');
	else {
		/* go up two lines*/
		cursor_up(2);
		putchar('\r');
	}

	fflush(stdout);
}

static void
hide_cursor(void)
{
	if (!fancy_tty)
		return;
	printf("\e[?25l");
	fflush(stdout);
}

static void
show_cursor(void)
{
	if (!fancy_tty)
		return;
	printf("\e[?25h");
	fflush(stdout);
}

static u64
ns_since_epoch(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		err(1, "clock_gettime");

	return boottime + ((u64)ts.tv_sec * (u64)NS_PER_S + (u64)ts.tv_nsec);
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
openfmt(int flags, const char *fmt, ...)
{
	va_list	ap;
	int	fd;
	char	path[PATH_MAX];
	int	r;

	va_start(ap, fmt);
	r = vsnprintf(path, sizeof(path), fmt, ap);
	if (r < 0 || r >= (int)sizeof(path)) {
		va_end(ap);
		return(-1);
	}
	fd = open(path, flags);
	va_end(ap);

	return (fd);
}

static void
sproc_cgroup_of_pid(u32 pid, char *buf, size_t len)
{
	int	 fd;
	char	*load_buf;
	size_t	 load_len;

	if ((fd = openfmt(O_RDONLY, "/proc/%d/cgroup", pid)) == -1)
		err(1, "can't open /proc/%d/cgroup", pid);
	if ((load_buf = load_file_nostat(fd, &load_len)) == NULL)
		err(1, "can't load /proc/%d/cgroup", pid);
	close(fd);
	if (load_buf[load_len - 1] != '\n')
		errx(1, "/proc/%d/cgroup expected newline", pid);
	load_buf[load_len - 1] = 0; /* chomp \n */
	if (load_len < 4)
		errx(1, "/proc/%d/cgroup is too short", pid);
	if (strncmp(load_buf, "0::", 3))
		errx(1, "no 0:: in /proc/%d/cgroup, likely not cgroup v2", pid);
	if (strlcpy(buf, load_buf + 3, len) >= len)
		errx(1, "cgroup truncated");
	free(load_buf);
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
	fprintf(stderr, "usage: %s -V\n",
	    program_invocation_short_name);

	exit(1);
}

static pid_t
fork_exec_nop1(int relative, uid_t id)
{
	pid_t		child;
	int		status;
	char *const	argv[] = {
		"true",
		"this",
		"is",
		"nop!",
		NULL
	};

	if ((child = fork()) == -1)
		err(1, "fork");
	/* child */
	else if (child == 0) {
		struct stat	 st;
		char		*true_path, *true_dir;

		if (stat("/usr/bin/true", &st) == 0) {
			true_path = "/usr/bin/true";
			true_dir = "/usr/bin";
		}
		else if (stat("/bin/true", &st) == 0) {
			true_path = "/bin/true";
			true_dir = "/bin";
		} else
			errx(1, "can't find true binary");

		if (setenv("IM_A_QUARK_TEST_CHILD", "OHYES", 1) == -1)
			err(1, "setenv");
		if (id != 0) {
			if (setresgid(id, id, id) == -1)
				err(1, "setresgid");
			if (setresuid(id, id, id) == -1)
				err(1, "setresuid");
			if (setsid() == -1)
				err(1, "setsid");
		}
		if (!relative)
			return (execv(true_path, argv));

		/*
		 * Chdir to the parent of true, /bin, or /usr/bin and so on...
		 */
		if (true_dir == NULL || *true_dir == 0)
			errx(1, "bad true_dir");
		if (chdir(true_dir) == -1)
			err(1, "chdir true_dir");
		return (execv("./true", argv));
	}

	/* parent */
	if (waitpid(child, &status, 0) == -1)
		err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		errx(1, "child didn't exit cleanly");

	return (child);
}

static pid_t
fork_exec_nop(void)
{
	return (fork_exec_nop1(0, 0));
}

static void
fork_n(int n)
{
	pid_t	pid;
	int	status;

	if (n == 0)
		return;

	if ((pid = fork()) == -1)
		err(1, "fork");
	/* parent */
	if (pid != 0) {
		if (waitpid(pid, &status, 0) == -1)
			err(1, "waitpid");
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			errx(1, "child didn't exit cleanly");

		return;
	} else {
		fork_n(--n);
		exit(0);
	}
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

static const struct quark_event *
drain_any(struct quark_queue *qq)
{
	return (drain_for_pid(qq, -1));
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
t_os_release(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue	 qq;
	struct quark_sysinfo	*si;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	si = &qq.sysinfo;

	assert(si->os_name != NULL);

	if (getenv("QUARK_INITRAMFS") != NULL) {
		assert(!strcmp(si->os_name, "quark kernel testing"));
		assert(!strcmp(si->os_version, "1.23.4 iota"));
		assert(!strcmp(si->os_release_type, "testing"));
		assert(!strcmp(si->os_id, "quark"));
		assert(!strcmp(si->os_version_id, "1.23.4"));
		assert(!strcmp(si->os_version_codename, "iota"));
		assert(!strcmp(si->os_pretty_name, "Quark kernel testing initramfs"));
	}

	quark_queue_close(&qq);

	return (0);
}

static int
fork_exec_exit(const struct test *t, struct quark_queue_attr *qa, int relative)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	const struct quark_process	*qp;
	pid_t				 child;
	struct quark_cmdline_iter	 qcmdi;
	const char			*arg;
	size_t				 expected_args_len;
	int				 argc;
	char				 path[PATH_MAX];
	u64				 before, after;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	before = ns_since_epoch();
	child = fork_exec_nop1(relative, 0);
	qev = drain_for_pid(&qq, child);
	after = ns_since_epoch();

	/* check qev.events */
	assert(qev->events & QUARK_EV_FORK);
	assert(qev->events & QUARK_EV_EXEC);
	assert(qev->events & QUARK_EV_EXIT);
	assert(qev->time >= before);
	assert(qev->time <= after);
	/* check qev.process */
	qp = qev->process;
	assert(qp != NULL);
	assert(qp->flags & QUARK_F_EXIT);
	assert(qp->flags & QUARK_F_COMM);
	assert(qp->flags & QUARK_F_FILENAME);
	assert(qp->flags & QUARK_F_CMDLINE);
	assert(qp->flags & QUARK_F_CWD);
	if (qa->flags & QQ_EBPF)
		assert(qp->flags & QUARK_F_CGROUP);
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
	assert(strlen(qp->proc_entity_id) == 16);
	/* XXX TODO check tty_major and tty_minor for self in the future */
#if 0
	assert(qp->proc_tty_major != QUARK_TTY_UNKNOWN);
	assert(qp->proc_tty_minor != 0);
#endif
	/* check strings */
	assert(!strcmp(qp->comm, "true"));
	assert(!strcmp(qp->filename, "/bin/true") ||
	    !strcmp(qp->filename, "/usr/bin/true"));
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
			assert(!strcmp(arg, "true"));
			break;
		case 1:
			assert(!strcmp(arg, "this"));
			break;
		case 2:
			assert(!strcmp(arg, "is"));
			break;
		case 3:
			assert(!strcmp(arg, "nop!"));
			break;
		default:
			errx(1, "unexpected argc");
		}
		argc++;
	}
	assert(argc == 4);
	assert(qp->cmdline_len == expected_args_len);

	if (getcwd(path, sizeof(path)) == NULL)
		err(1, "getcwd");
	/*
	 * If we did a relative exec, the child changes current directory to
	 * either /bin or /usr/bin
	 */
	if (relative)
		assert(!strcmp("/bin", qp->cwd) || !strcmp("/usr/bin",
		    qp->cwd));
	else
		assert(!strcmp(path, qp->cwd));

	/*
	 * We haven't changed the cgroup, so the child cgroup should be the same
	 * as getpid()
	 */
	if (qa->flags & QQ_EBPF) {
		sproc_cgroup_of_pid(getpid(), path, sizeof(path));
		assert(!strcmp(path, qp->cgroup));
	}

	/*
	 * Check env, we should have set IM_A_QUARK_TEST_CHILD=OHYES
	 */
	if (qa->flags & QQ_EBPF) {
		const char *needle = "IM_A_QUARK_TEST_CHILD=OHYES";

		assert(qp->flags & QUARK_F_ENV);
		assert(memmem(qp->env, qp->env_len, needle, strlen(needle)) != NULL);
	}

	quark_queue_close(&qq);

	return (0);
}

static int
t_fork_exec_exit(const struct test *t, struct quark_queue_attr *qa)
{
	return (fork_exec_exit(t, qa, 0));
}

static int
t_fork_exec_exit_rel(const struct test *t, struct quark_queue_attr *qa)
{
	return (fork_exec_exit(t, qa, 1));
}

static int
t_id_change(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	const struct quark_process	*qp;
	pid_t				 child;
	uid_t				 id;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	id = 4242;
	child = fork_exec_nop1(0, id);
	qev = drain_for_pid(&qq, child);

	/* EXEC and EXIT must _not_ have been aggregated */
	assert(qev->events == (QUARK_EV_FORK | QUARK_EV_ID_CHANGE));
	assert(qev->id_change == (QUARK_ID_CHANGE_SETSID |
	    QUARK_ID_CHANGE_SETUID | QUARK_ID_CHANGE_SETGID));

	qp = qev->process;
	assert(qp != NULL);
	assert(qp->proc_uid == id);
	assert(qp->proc_gid == id);
	assert(qp->proc_suid == id);
	assert(qp->proc_sgid == id);
	assert(qp->proc_euid == id);
	assert(qp->proc_egid == id);
	/* make sure pgid and sid changed */
	assert((pid_t)qp->proc_pgid != getpgid(0));
	assert((pid_t)qp->proc_sid != getsid(0));

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
t_file(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	struct quark_file		*qf;
	struct stat			 st;
	char				 path[] = "/tmp/quark-test.XXXXXX";
	int				 fd;
	u64				 before, after;

	qa->flags |= QQ_FILE;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	before = ns_since_epoch();
	if ((fd = mkstemp(path)) == -1)
		err(1, "mkstemp");
	after = ns_since_epoch();
	assert(write(fd, "1", 1) == 1);
	assert(write(fd, "2", 1) == 1);
	assert(write(fd, "3", 1) == 1);
	assert(write(fd, "4", 1) == 1);
	assert(write(fd, "5", 1) == 1);

	if (unlink(path) == -1)
		err(1, "unlink");

	/*
	 * unlink(2) might change atime, so unlink before we fstat(2)
	 */
	if (fstat(fd, &st) == -1)
		err(1, "stat");

	close(fd);

	qev = drain_for_pid(&qq, getpid());
	assert(qev->events == QUARK_EV_FILE);
	assert(qev->time >= before);
	assert(qev->time <= after);
	qf = qev->file;
	assert(qf != NULL);
	assert(qf->op_mask & QUARK_FILE_OP_CREATE);
	assert(qf->op_mask & QUARK_FILE_OP_MODIFY);
	assert(qf->op_mask & QUARK_FILE_OP_REMOVE);
	assert(qf->inode == st.st_ino);
	assert(qf->atime == TS_TO_NS(&st.st_atim));
	/*
	 * ctime is normalized, see
	 * inode_set_ctime_to_ts()->set_normalized_timespec64()
	 * TODO: Figure out how to make it match at some point.
	 */
	/* assert(qf->ctime == TS_TO_NS(&st.st_ctim)); */
	assert(qf->ctime > 0);
	assert(qf->mtime == TS_TO_NS(&st.st_mtim));
	assert(qf->mode == st.st_mode);
	assert(qf->uid == getuid());
	assert(qf->gid == getgid());

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

static int
t_file_bypass(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;

	qa->flags &= ~QQ_ENTRY_LEADER;
	qa->flags |= QQ_BYPASS | QQ_FILE;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	quark_queue_close(&qq);

	return (0);
}

static int
t_memfd(const struct test *t, struct quark_queue_attr *qa)
{
#ifdef NO_MEMFD
	warnx("%s: compiled with NO_MEMFD, skipping", __func__);
#else
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	const struct quark_shm		*qshm;
	int				 fd;
#if 0
	int				 fd2;
	char				 buf[1024];
#endif
	/*
	 * MEMFD_OPEN still requires QQ_FILE for now
	 */
	qa->flags |= QQ_SHM | QQ_FILE;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	/*
	 * Test MEMFD_CREATE
	 */
	if ((fd = memfd_create("t_memfd-glorious-test", MFD_CLOEXEC)) == -1) {
		if (errno == ENOTSUP) {
			warn("old kernel, skipping memfd_create");
			quark_queue_close(&qq);

			return (0);
		}
		err(1, "memfd_create");
	}
	qev = drain_for_pid(&qq, getpid());

	assert(qev->events & QUARK_EV_SHM);
	qshm = qev->shm;
	assert(qshm->kind == QUARK_SHM_MEMFD_CREATE);
	assert(qshm->memfd_create_flags == MFD_CLOEXEC);
	assert(!strcmp(qshm->path, "t_memfd-glorious-test"));

#if 0
	/*
	 * XXX MEMFD_OPEN is broken, hence the test is disabled, see
	 * https://github.com/elastic/quark/issues/255
	 */
	snprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd);
	if ((fd2 = open(buf, O_RDWR)) == -1)
		err(1, "open");

	qev = drain_for_pid(&qq, getpid());
	qshm = qev->shm;
	assert(qshm->kind == QUARK_SHM_MEMFD_OPEN);
	assert(!strcmp(qshm->path, "t_memfd-glorious-test"));
	close(fd2);
#endif

	close(fd);
	quark_queue_close(&qq);
#endif	/* NO_MEMFD */

	return (0);
}

static int
t_shmget(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	const struct quark_shm		*qshm;
	int				 id;

	qa->flags |= QQ_SHM;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	if ((id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600)) == -1)
		err(1, "shmget");
	qev = drain_for_pid(&qq, getpid());

	assert(qev->events & QUARK_EV_SHM);
	qshm = qev->shm;
	assert(qshm->kind == QUARK_SHM_SHMGET);
	assert(qshm->shmget_key == IPC_PRIVATE);
	assert(qshm->shmget_shmflg == (IPC_CREAT | 0600));
	assert(qshm->shmget_size == 4096);

	if (shmctl(id, IPC_RMID, NULL) == -1)
		err(1, "shmctl");

	quark_queue_close(&qq);

	return (0);
}

static int
t_shm_open(const struct test *t, struct quark_queue_attr *qa)
{
#ifdef NO_SHM_OPEN
	warnx("%s: compiled without SHM_OPEN", __func__);
#else
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	const struct quark_shm		*qshm;
	int				 fd, fd2;

	qa->flags |= QQ_SHM | QQ_FILE;

	/*
	 * Probes are bugged, a O_CREAT that actually creates a file, shows up
	 * as a FILE events, not a SHM_OPEN.
	 * See https://github.com/elastic/quark/issues/256
	 */
	if ((fd = shm_open("/shm_open-ohmyohmy", O_CREAT | O_RDWR, 0600)) == -1)
		err(1, "shm_open");

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	if ((fd2 = shm_open("/shm_open-ohmyohmy", O_RDWR, 0600)) == -1)
		err(1, "shm_open");

	qev = drain_for_pid(&qq, getpid());
	qshm = qev->shm;

	assert(qev->events & QUARK_EV_SHM);
	assert(qshm->kind == QUARK_SHM_SHM_OPEN);
	assert(!strcmp(qshm->path, "/dev/shm/shm_open-ohmyohmy"));

	close(fd2);
	close(fd);
	if (shm_unlink("/shm_open-ohmyohmy") == -1)
		err(1, "shm_unlink");

	quark_queue_close(&qq);
#endif	/* NO_SHM_OPEN */

	return (0);
}

static int
t_tty_load(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;

	qa->flags |= QQ_TTY;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	quark_queue_close(&qq);

	return (0);
}

static int
t_tty(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	struct quark_tty		*qtty;
	pid_t				 pid;
	struct winsize			 winsize;
	const char			*data	  = "oh hai from the tty test ";
	size_t				 data_len = strlen(data);
	int				 status;

	if (!isatty(STDOUT_FILENO)) {
		warnx("stdout is not a tty, skipping");
		return (0);
	}

	if (getenv("QUARK_INITRAMFS") != NULL) {
		warnx("no tty events in initramfs, skipping");
		return (0);
	}

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) == -1)
		err(1, "ioctl TIOCGWINSZ");

	qa->flags |= QQ_TTY;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	if ((pid = fork()) == -1)
		err(1, "fork");

	/* child */
	if (pid == 0) {
		fputs(data, stdout);
		fflush(stdout);
		fputs(data, stdout);
		fflush(stdout);
		fputs(data, stdout);
		fflush(stdout);
		exit(0);
	}

	/* parent */
	if (waitpid(pid, &status, 0) == -1)
		err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		errx(1, "tty child didn't exit cleanly");

	qev = drain_for_pid(&qq, pid); /* FORK */
	qev = drain_for_pid(&qq, pid); /* TTY */

	assert(qev->events == QUARK_EV_TTY);
	qtty = qev->tty;
	assert(qtty->cols == winsize.ws_col);
	assert(qtty->rows == winsize.ws_row);
	assert(qtty->total_len == 3 * data_len);
	assert(qtty->data_len == data_len);
	assert(!memcmp(qtty->data, data, data_len));
	assert(!memcmp(qtty->next->data, data, data_len));
	assert(!memcmp(qtty->next->next->data, data, data_len));
	assert(qtty->next->next->next == NULL);
	assert(qtty->truncated == 0);

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
	assert(qev->socket->conn_origin == SOCK_CONN_CONNECT);
	assert((pid_t)qev->socket->pid_origin == child);
	assert((pid_t)qev->socket->pid_last_use == child);
	assert(qev->socket->local.af == AF_INET);
	assert(qev->socket->local.u.addr4 == htonl(INADDR_LOOPBACK));
	assert(qev->socket->local.port == bound_port);
	assert(qev->socket->remote.af == AF_INET);
	assert(qev->socket->remote.u.addr4 == htonl(INADDR_LOOPBACK));
	assert(qev->socket->remote.port == htons(18888));
	assert(qev->socket->close_time == 0);
	assert(qev->socket->bytes_received == 0);
	assert(qev->socket->bytes_sent == 0);

	/* SOCK_CONN_CLOSED */
	qev = drain_for_pid(&qq, child);
	assert(qev->events == QUARK_EV_SOCK_CONN_CLOSED);
	assert(qev->process != NULL);
	assert((pid_t)qev->process->pid == child);
	assert(qev->socket != NULL);
	assert(qev->socket->established_time > 0);
	assert(qev->socket->conn_origin == SOCK_CONN_CONNECT);
	assert((pid_t)qev->socket->pid_origin == child);
	assert((pid_t)qev->socket->pid_last_use == child);
	assert(qev->socket->local.af == AF_INET);
	assert(qev->socket->local.u.addr4 == htonl(INADDR_LOOPBACK));
	assert(qev->socket->local.port == bound_port);
	assert(qev->socket->remote.af == AF_INET);
	assert(qev->socket->remote.u.addr4 == htonl(INADDR_LOOPBACK));
	assert(qev->socket->remote.port == htons(18888));
	assert(qev->socket->close_time > 0);
	assert(qev->socket->bytes_received == 0);
	assert(qev->socket->bytes_sent == strlen(PATTERN));

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

static int
t_cgroup_parse(const struct test *t, struct quark_queue_attr *qa)
{
	char	cid[NAME_MAX];
	int	i, r;

	struct {
		const char	*in;
		const char	*out;
		int		 expected_ret;	/* -1 fail, 0 found, any other fail */
	} cases[] = {
		{ "foo/docker-f6aa2e3fa923d32f4d7905727cf1011148e4da0fd101492e98a27e8c55c5c829.scope",
		  "docker://f6aa2e3fa923d32f4d7905727cf1011148e4da0fd101492e98a27e8c55c5c829",
		  0 },
		{ "foo/cri-containerd-abc123def456.scope", "containerd://abc123def456", 0 },
		{ "foo/containerd-abc123def456.scope", "containerd://abc123def456", 0 },
		{ "foo/crio-0123456789abcdef.scope", "cri-o://0123456789abcdef", 0 },
		/* negative cases */
		{ "crio-0123456789abcdef.scope", "cri-o://0123456789abcdef", -1 },
		{ "docker-.scope", NULL, -1 },
		{ "containerd-.scope", NULL, -1 },
		{ "crio-.scope", NULL, -1 },
		{ "nothex", NULL, -1 },
		{ "ABCDEF", NULL, -1 },
		{ "something-abcdef.scope", NULL, -1 },
		{ "docker-abcdef.scopeX", NULL, -1 },
		{ NULL, NULL, -1 }
	};

	for (i = 0; cases[i].in != NULL; i++) {
		bzero(cid, sizeof(cid));

		r = kube_parse_cgroup(cases[i].in, cid, sizeof(cid));
		assert(r == cases[i].expected_ret);
		if (r == 0)
			assert(!strcmp(cid, cases[i].out));
	}

	return (0);
}

static int
t_hanson(const struct test *t, struct quark_queue_attr *qa)
{
	struct hanson	 h;
	char		*buf;
	size_t		 buf_len;
	int		 basic_first = 1;
	const char	*expected =
	    "{\"basic\":{"
	    "\"foo\":\"bar\","
	    "\"zero\":0,"
	    "\"one\":1,"
	    "\"two\":2,"
	    "\"neg_one\":-1,"
	    "\"int64_min\":-9223372036854775808,"
	    "\"int64_min_plus_one\":-9223372036854775807,"
	    "\"int64_max\":9223372036854775807"
	    "}}";

	assert(hanson_open(&h) == 0);

	hanson_add_object(&h, "basic", NULL);
	/* Test escaped strings */
	hanson_add_key_value(&h, "foo", "bar", &basic_first);
	hanson_add_key_value_int(&h, "zero", 0, &basic_first);
	hanson_add_key_value_int(&h, "one", 1, &basic_first);
	hanson_add_key_value_int(&h, "two", 2, &basic_first);
	hanson_add_key_value_int(&h, "neg_one", -1, &basic_first);
	hanson_add_key_value_int(&h, "int64_min", INT64_MIN, &basic_first);
	hanson_add_key_value_int(&h, "int64_min_plus_one", -9223372036854775807LL, &basic_first);
	hanson_add_key_value_int(&h, "int64_max", INT64_MAX, &basic_first);
	hanson_close_object(&h);

	assert(hanson_close(&h, &buf, &buf_len) == 0);

	if (strcmp(buf, expected)) {
		errx(1, "json doesn't match\n got: %s\nwant: %s\n",
		    buf, expected);
	}
	free(buf);

	return (0);
}

static int
t_hanson_escape(const struct test *t, struct quark_queue_attr *qa)
{
	struct hanson	 h;
	char		*buf;
	size_t		 buf_len;
	int		 esc_first = 1;
	const char	*expected =
	    "{\"mytest\":{"
	    "\"esc_bslash\":\"_\\\\_\","
	    "\"esc_dquote\":\"_\\\"_\","
	    "\"esc_bspace\":\"_\\b_\","
	    "\"esc_feed\":\"_\\f_\","
	    "\"esc_nl\":\"_\\n_\","
	    "\"esc_cr\":\"_\\r_\","
	    "\"esc_tab\":\"_\\t_\","
	    "\"esc_unicode\":\"_\\u0001_\""
	    "}}";

	assert(hanson_open(&h) == 0);

	hanson_add_object(&h, "mytest", NULL);
	/* Test escaped strings */
	hanson_add_key_value(&h, "esc_bslash", "_\\_", &esc_first);
	hanson_add_key_value(&h, "esc_dquote", "_\"_", &esc_first);

	hanson_add_key_value(&h, "esc_bspace", "_\b_", &esc_first);
	hanson_add_key_value(&h, "esc_feed", "_\f_", &esc_first);
	hanson_add_key_value(&h, "esc_nl", "_\n_", &esc_first);
	hanson_add_key_value(&h, "esc_cr", "_\r_", &esc_first);
	hanson_add_key_value(&h, "esc_tab", "_\t_", &esc_first);
	hanson_add_key_value(&h, "esc_unicode", "_\1_", &esc_first);
	hanson_close_object(&h);

	assert(hanson_close(&h, &buf, &buf_len) == 0);

	if (strcmp(buf, expected)) {
		errx(1, "json doesn't match\n got: %s\nwant: %s\n",
		    buf, expected);
	}
	free(buf);

	return (0);
}

static int
t_rule_path(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	struct quark_ruleset		 ruleset;
	struct quark_rule		*rule;
	char				 path1[] = "/tmp/quark-test-path1.XXXXXX";
	char				 path2[] = "/tmp/quark-test-path2.XXXXXX";
	int				 fd1, fd2;

	if ((fd1 = mkstemp(path1)) == -1)
		err(1, "mkstemp");
	if ((fd2 = mkstemp(path2)) == -1)
		err(1, "mkstemp");

	/*
	 * Make a rule that will drop file events to path1 from ourselves.
	 * We then write to both path1 and path2, we should see only the path2
	 * write.
	 */
	quark_ruleset_init(&ruleset);
	rule = quark_ruleset_append_rule(&ruleset, RA_DROP, 0);
	assert(rule != NULL);
	assert(!quark_rule_match_pid(rule, getpid()));
	assert(!quark_rule_match_file_path(rule, "/tmp/quark-test-path1*"));
	assert(rule->action == RA_DROP);
	assert(rule->n_fields == 2);

	qa->ruleset = &ruleset;
	qa->flags |= QQ_FILE;

	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	/* Write to a path1 */
	assert(write(fd1, "1", 1) == 1);
	close(fd1);
	if (unlink(path1) == -1)
		err(1, "unlink");
	/* Write to a path2 */
	assert(write(fd2, "1", 1) == 1);
	close(fd2);
	if (unlink(path2) == -1)
		err(1, "unlink");
	/* Fetch the path2 event */
	qev = drain_for_pid(&qq, getpid());
	assert(qev->events & QUARK_EV_FILE);
	assert(!strcmp(qev->file->path, path2));
	/* Make sure it hits the rule once */
	assert(rule->hits == 1);
	assert(rule->evals > rule->hits);

	quark_queue_close(&qq);
	quark_ruleset_clear(&ruleset);

	return (0);
}

static int
t_rule_poison(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	struct quark_ruleset		 ruleset;
	struct quark_rule		*rule;
	u64				 poison_tag;
	int				 i;

	/*
	 * We will add 3 rules.
	 * First rule poisons all our children with poison_tag.
	 * Second rule PASSes everything with poison_tag.
	 * Third rule DROPs everything else.
	 * We then fork children up to gran-gran-children(4 levels) and wait for
	 * their events.
	 */

	poison_tag = 1805;
	quark_ruleset_init(&ruleset);

	/* First add a rule to poison our children BUT THINK OF THE CHILDREN! */
	rule = quark_ruleset_append_rule(&ruleset, RA_POISON, poison_tag);
	assert(rule != NULL);
	assert(!quark_rule_match_ppid(rule, getpid()));

	/* Now add a rule to PASS on our children */
	rule = quark_ruleset_append_rule(&ruleset, RA_PASS, 0);
	assert(rule != NULL);
	assert(!quark_rule_match_poison(rule, poison_tag));

	/* Now block everything else */
	rule = quark_ruleset_append_rule(&ruleset, RA_DROP, 0);
	assert(rule != NULL);

	/* Start the ball */
	qa->ruleset = &ruleset;
	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	/*
	 * Fork up to gran-gran-children, this only returns when they've all
	 * been waited for by their parents
	 */
	fork_n(4);

	/* There should be now exactly 4 events, all with FORK+EXIT */
	for (i = 0; i < 4; i++) {
		qev = drain_any(&qq);
		assert(qev->events == (QUARK_EV_FORK | QUARK_EV_EXIT));
		assert(qev->process != NULL);
		assert(qev->process->poison_tag == poison_tag);
	}

	quark_queue_close(&qq);
	quark_ruleset_clear(&ruleset);

	return (0);
}

static int
t_rule_id(const struct test *t, struct quark_queue_attr *qa)
{
	struct quark_queue		 qq;
	const struct quark_event	*qev;
	struct quark_ruleset		 ruleset;
	struct quark_rule		*rule;
	uid_t				 uid;
	struct timespec			 start, now;

	/*
	 * We will add 2 rules.
	 * First rule accepts only events from uid 66666.
	 * Second rule drops all events.
	 * We then generate one event from uid 0, and another from 66666, if we
	 * ever see the one with uid 0, it failed.
	 */

	uid = 66666;
	quark_ruleset_init(&ruleset);

	/* Accept events that match uid 66666 */
	rule = quark_ruleset_append_rule(&ruleset, RA_PASS, 0);
	assert(rule != NULL);
	assert(!quark_rule_match_uid(rule, 66666));

	/* Now block everything else */
	rule = quark_ruleset_append_rule(&ruleset, RA_DROP, 0);
	assert(rule != NULL);

	/* Start the ball */
	qa->ruleset = &ruleset;
	if (quark_queue_open(&qq, qa) != 0)
		err(1, "quark_queue_open");

	/*
	 * fork a process in uid 0 followed by uid 66666.
	 */
	fork_exec_nop();
	(void)fork_exec_nop1(0, uid);

	/* There should be now exactly 4 events, all with FORK+EXIT */
	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
		err(1, "clock_gettime");
	for (now = start; ;(void)clock_gettime(CLOCK_MONOTONIC, &now)) {
		if ((now.tv_sec - start.tv_sec) >= 5) {
			errno = ETIME;
			err(1, "timed out waiting event");
		}
		qev = drain_any(&qq);
		assert(qev->process != NULL);
		assert(qev->process->flags & QUARK_F_PROC);
		assert(qev->process->proc_euid == uid);
		break;
	}

	quark_queue_close(&qq);
	quark_ruleset_clear(&ruleset);

	return (0);
}

/*
 * Try to order by increasing order of complexity
 * Use T() for tests that require no queue.
 * Define the test twice if for KPROBE and EBPF
 */
#define T(_x)		{ S(_x), _x, 0, 0 }
#define T_KPROBE(_x)	{ S(_x), _x, QQ_KPROBE, 0 }
#define T_EBPF(_x)	{ S(_x), _x, QQ_EBPF, 0 }
#define S(_x)		#_x
struct test all_tests[] = {
	T_EBPF(t_probe),
	T_KPROBE(t_probe),
	T_EBPF(t_os_release),
	T_KPROBE(t_os_release),
	T_EBPF(t_fork_exec_exit),
	T_KPROBE(t_fork_exec_exit),
	T_EBPF(t_fork_exec_exit_rel),
	T_EBPF(t_id_change),
	T_EBPF(t_exit_tgid),
	T_KPROBE(t_exit_tgid),
	T_EBPF(t_file),
	T_EBPF(t_bypass),
	T_EBPF(t_file_bypass),
	T_EBPF(t_memfd),
	T_EBPF(t_shmget),
	T_EBPF(t_shm_open),
	T_EBPF(t_tty_load),
	T_EBPF(t_tty),
	T_EBPF(t_sock_conn),
	T_EBPF(t_dns),
	T_EBPF(t_cgroup_parse),
	T_EBPF(t_namespace),
	T_KPROBE(t_namespace),
	T_EBPF(t_cache_grace),
	T_KPROBE(t_cache_grace),
	T_EBPF(t_min_agg),
	T_KPROBE(t_min_agg),
	T_EBPF(t_stats),
	T_KPROBE(t_stats),
	T(t_hanson),
	T(t_hanson_escape),
	T_EBPF(t_rule_path),
	T_EBPF(t_rule_poison),
	T_EBPF(t_rule_id),
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

static void
toggle_test(const char *name, int excluded)
{
	struct test	*t;
	int		 matches;

	matches = 0;
	for (t = all_tests; t->name != NULL; t++) {
		if (strcmp(t->name, name))
			continue;
		t->excluded = excluded;
		matches++;
	}

	if (!matches)
		errx(1, "no test named %s", name);
}

#define exclude_test(_n) toggle_test(_n, 1)
#define include_test(_n) toggle_test(_n, 0)

static int
run_test_doit(struct test *t, struct quark_queue_attr *qa)
{
	int			r, before_nfd, after_nfd;;
	struct quark_queue_attr qa_copy;

	/*
	 * Check for FD leaks
	 */
	before_nfd = num_open_fd();
	if (qa == NULL)
		qa = NULL;
	else {
		qa_copy = *qa;
		qa = &qa_copy;
	}
	r = t->func(t, qa);
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
run_test(struct progress *progress, struct test *t, struct quark_queue_attr *qa)
{
	pid_t		 child;
	int		 status, x, linepos, be, r;
	int		 child_stderr[2];
	FILE		*child_stream;
	char		*child_buf;
	size_t		 child_buflen;
	ssize_t		 n;

	progress_print(progress);

	/*
	 * Figure out if this is ebpf or kprobe
	 */
	be = backend_of_attr(qa);

	linepos = printf("%s", t->name);
	if (be != -1) {
		linepos += printf(" @ %s",
		    be == QQ_EBPF ? "ebpf" : "kprobe");
	}

	while (++linepos < STATUS_LINELEN)
		putchar('.');

	fflush(stdout);

	if (noforkflag) {
		r = run_test_doit(t, qa);
		if (r == 0) {
			x = color(GREEN);
			printf("ok\n");
			color(x);
			progress_add(progress, GREEN);
		} else {
			x = color(RED);
			printf("failed\n");
			color(x);
			progress_add(progress, RED);
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
		tv.tv_usec = 100000; /* 100ms */

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

	if (WIFEXITED(status)) {
		progress_add(progress, WEXITSTATUS(status) == 0 ? GREEN : RED);
		return (WEXITSTATUS(status));
	}

	progress_add(progress, RED);

	return (-1);
}

static int
run_tests(int argc, char *argv[])
{
	struct test		*t;
	int			 failed, i;
	struct quark_queue_attr	 bpf_attr;
	struct quark_queue_attr	 kprobe_attr;
	struct quark_queue_attr	*attr;
	struct progress		 progress;

	quark_queue_default_attr(&bpf_attr);
	bpf_attr.flags &= ~QQ_ALL_BACKENDS;
	bpf_attr.flags |= QQ_EBPF | QQ_ENTRY_LEADER;
	bpf_attr.hold_time = 100;
	bpf_attr.max_env = 32768;

	quark_queue_default_attr(&kprobe_attr);
	kprobe_attr.flags &= ~QQ_ALL_BACKENDS;
	kprobe_attr.flags |= QQ_KPROBE | QQ_ENTRY_LEADER;
	kprobe_attr.hold_time = 100;
	kprobe_attr.max_env = 32768;

	bzero(&progress, sizeof(progress));
	failed = 0;

	/*
	 * If argc != 0, only consider specified tests.
	 */
	if (argc != 0) {
		for (t = all_tests; t->name != NULL; t++)
			t->excluded = 1;
		for (i = 0; i < argc; i++)
			for (t = all_tests; t->name != NULL; t++)
				if (!strcmp(t->name, argv[i]))
					include_test(t->name);
	}

	/*
	 * Maybe exclude tests depending on the backend
	 */
	for (t = all_tests; t->name != NULL; t++) {
		if ((t->backend == QQ_EBPF && !bflag) ||
		    (t->backend == QQ_KPROBE && !kflag))
			t->excluded = 1;
	}

	for (t = all_tests; t->name != NULL; t++) {
		if (t->excluded)
			continue;
		progress.total++;
	}

	if (progress.total == 0)
		errx(1, "nothing to run");

	hide_cursor();
	for (t = all_tests; t->name != NULL; t++) {
		if (t->excluded)
			continue;
		if (t->backend == QQ_EBPF)
			attr = &bpf_attr;
		else if (t->backend == QQ_KPROBE)
			attr = &kprobe_attr;
		else
			attr = NULL;
		if (run_test(&progress, t, attr) != 0)
			failed++;
	}
	progress_print(&progress);
	show_cursor();

	return (failed);
}

static void
sigint_handler(int sig)
{
	show_cursor();
	raise(sig);
}

int
main(int argc, char *argv[])
{
	int			 ch, failed, x;
	struct sigaction	 sigact;

	fancy_tty = probe_fancy_tty();
	in_valgrind = getenv("VALGRIND") != NULL;

	while ((ch = getopt(argc, argv, "1bhklvVx:")) != -1) {
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
		case 'v':
			quark_verbose++;
			break;
		case 'V':
			display_version();
			break;	/* NOTREACHED */
		case 'x':
			exclude_test(optarg);
			break;
		default:
			usage();
		}
	}

	boottime = fetch_boottime();

	if (!bflag && !kflag)
		bflag = kflag = 1;

	argc -= optind;
	argv += optind;

	bzero(&sigact, sizeof(sigact));
	sigact.sa_flags = SA_RESTART | SA_RESETHAND;
	sigact.sa_handler = &sigint_handler;
	if (sigaction(SIGINT, &sigact, NULL) == -1)
		warn("sigaction");

	failed = run_tests(argc, argv);

	x = failed == 0 ? color(GREEN) : color(RED);
	printf("%d failures\n", failed);
	color(x);

	return (failed);
}
