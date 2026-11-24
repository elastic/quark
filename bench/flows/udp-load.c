// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

/*
 * udp-load: generate the UDP traffic flow-bench.sh needs.
 *
 * Nothing here knows about quark. CPU 0 is left alone as that is where
 * with-quark is pinned to.
 *
 * udp-load flows <nflows>
 *	Many flows, few packets. One socket sends one datagram per period to
 *	each of nflows ports of the destination, evenly spread over the
 *	period, until it gets a SIGTERM or SIGINT. Nobody has to listen
 *	there, but whoever does gets our datagrams, and to anything watching
 *	the destination this is a sweep of its ports from FLOWS_PORT up.
 *	Prints "sent_percent N", how much of that it managed.
 *
 * udp-load pps
 *	Few flows, many packets. Each thread gets a CPU and a connected socket
 *	of its own, and sends to PPS_PORT of the destination as fast as it
 *	can, one datagram per system call, for a given time: a flood, as far
 *	as the destination can tell. Prints "pps N", the datagrams per second
 *	the kernel took from all of them, and "refused_percent N", how many
 *	of their sends it turned away, mostly for lack of room in the device
 *	queue.
 */

#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define NS_PER_S	1000000000ULL
#define NS_PER_MS	1000000ULL

#define FIRST_CPU	1	/* thread i is pinned to FIRST_CPU + i */
				/* CPU 0 is left alone for with-quark */

#define FLOWS_PORT	1024	/* flows: flow i goes to FLOWS_PORT + i */
#define PPS_PORT	22000   /* UDP destination port for pps command, keep it != 53 */

struct count {
	uint64_t	sent;
	uint64_t	failed;
};

struct sender {
	pthread_t	thread;
	int		cpu;
	int		fd;
	struct count	count;
};

static struct sockaddr_in	dst;
static const char		*ifname;	/* through which device */
static const char		payload[64];

/*
 * Set once, by the main thread or by a signal handler, otherwise polled.
 */
static int			go, stop;

static int
flag_get(int *flag)
{
	return (__atomic_load_n(flag, __ATOMIC_RELAXED));
}

static void
flag_set(int *flag)
{
	__atomic_store_n(flag, 1, __ATOMIC_RELAXED);
}

static uint64_t
now(void)
{
	struct timespec	ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		err(1, "clock_gettime");

	return ((uint64_t)ts.tv_sec * NS_PER_S + ts.tv_nsec);
}

static void
pin(int cpu)
{
	cpu_set_t	set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) == -1)
		err(1, "can't run on CPU %d", cpu);
}

static int
udp_socket(void)
{
	int	s;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");
	if (ifname != NULL && setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
	    ifname, strlen(ifname) + 1) == -1)
		err(1, "SO_BINDTODEVICE %s", ifname);

	return (s);
}

/*
 * Sends one datagram, never waiting for buffer space: a sender asleep
 * would look like a slow kernel. Failed sends are captured regardless: there
 * was no room in the device queue, or the destination answered an earlier
 * datagram with an ICMP error, as it does when nobody is on the port or its
 * firewall rejects.
 */
static void
send1(int fd, const struct sockaddr_in *to, struct count *c)
{
	ssize_t	n;

	if (to == NULL)
		n = send(fd, payload, sizeof(payload), MSG_DONTWAIT);
	else
		n = sendto(fd, payload, sizeof(payload), MSG_DONTWAIT,
		    (const struct sockaddr *)to, sizeof(*to));
	if (n != -1)
		c->sent++;
	else if (errno == EAGAIN || errno == ENOBUFS || errno == ECONNREFUSED ||
	    errno == EHOSTUNREACH || errno == ENETUNREACH)
		c->failed++;
	else
		err(1, "send");
}


static void
sigstop(int sig)
{
	flag_set(&stop);
}

static void
flows(int nflows, int period_ms)
{
	struct sockaddr_in	to;
	struct sigaction	sa;
	struct count		c = { 0, 0 };
	uint64_t		start, elapsed, due, n;
	int			fd;

	/* We go on until told to stop */
	bzero(&sa, sizeof(sa));
	sa.sa_handler = sigstop;
	if (sigaction(SIGTERM, &sa, NULL) == -1 ||
	    sigaction(SIGINT, &sa, NULL) == -1)
		err(1, "sigaction");

	pin(FIRST_CPU);
	fd = udp_socket();
	to = dst;
	n = 0;
	start = now();
	while (!flag_get(&stop)) {
		elapsed = now() - start;
		/* How many should have left by now */
		due = elapsed * nflows / (period_ms * NS_PER_MS);
		for (; n < due && !flag_get(&stop); n++) {
			to.sin_port = htons(FLOWS_PORT + n % nflows);
			send1(fd, &to, &c);
		}
		usleep(1000);
	}
	due = (now() - start) * nflows / (period_ms * NS_PER_MS);
	printf("sent_percent %.1f\n",
	    due == 0 || c.sent >= due ? 100.0 : 100.0 * c.sent / due);
}

/*
 * If the destination is this machine somebody has to be there, or the kernel
 * answers every datagram with an ICMP error. A socket nobody reads will do: a
 * full receive buffer is the cheapest way to take a datagram which still gets
 * it all the way up to the socket. If the destination is on another machine
 * it may answer with ICMP errors too, when nobody is on the port or its
 * firewall rejects. Those are harmless: the kernel there limits them to about
 * one a second, and each fails one of our sends, which send1() counts.
 */
static void
sink(void)
{
	int	s;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");
	if (bind(s, (struct sockaddr *)&dst, sizeof(dst)) == -1 &&
	    errno != EADDRNOTAVAIL)
		err(1, "bind");
}

static void *
pps_thread(void *arg)
{
	struct sender	*s = arg;
	struct count	 c = { 0, 0 };

	pin(s->cpu);
	while (!flag_get(&go))
		usleep(100);
	while (!flag_get(&stop))
		send1(s->fd, NULL, &c);
	s->count = c;

	return (NULL);
}

static void
pps(int threads, int seconds)
{
	struct sender	*s;
	struct count	 c = { 0, 0 };
	uint64_t	 start, elapsed;
	int		 i;

	dst.sin_port = htons(PPS_PORT);
	sink();
	if ((s = calloc(threads, sizeof(*s))) == NULL)
		err(1, "calloc");
	for (i = 0; i < threads; i++) {
		s[i].cpu = FIRST_CPU + i;
		s[i].fd = udp_socket();
		if (connect(s[i].fd, (struct sockaddr *)&dst,
		    sizeof(dst)) == -1)
			err(1, "connect");
		if (pthread_create(&s[i].thread, NULL, pps_thread, &s[i]) != 0)
			errx(1, "pthread_create");
	}
	usleep(100000);		/* let them reach their cpus */
	start = now();
	flag_set(&go);
	sleep(seconds);
	flag_set(&stop);
	elapsed = now() - start;
	for (i = 0; i < threads; i++) {
		pthread_join(s[i].thread, NULL);
		c.sent += s[i].count.sent;
		c.failed += s[i].count.failed;
	}
	printf("pps %.0f\n", (double)c.sent * NS_PER_S / elapsed);
	printf("refused_percent %.1f\n", c.sent + c.failed == 0 ? 0.0 :
	    100.0 * c.failed / (c.sent + c.failed));
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s flows [-d addr] [-i ifname] [-P period_ms] "
	    "nflows\n", program_invocation_short_name);
	fprintf(stderr, "       %s pps [-d addr] [-i ifname] [-j threads] "
	    "[-t seconds]\n", program_invocation_short_name);

	exit(1);
}

static int
number(const char *what, const char *s, int min, int max)
{
	char	*end;
	long	 v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || end == s || *end != 0 || v < min || v > max)
		errx(1, "invalid %s: %s", what, s);

	return (v);
}

int
main(int argc, char *argv[])
{
	const char	*cmd;
	int		 ch, period_ms, seconds, threads;

	if (argc < 2)
		usage();
	cmd = argv[1];
	argc--;
	argv++;

	period_ms = 3000;
	seconds = 5;
	threads = 1;
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	/* Each command has its own options */
	while ((ch = getopt(argc, argv,
	    !strcmp(cmd, "flows") ? "d:i:P:" : "d:i:j:t:")) != -1) {
		switch (ch) {
		case 'd':
			if (inet_pton(AF_INET, optarg, &dst.sin_addr) != 1)
				errx(1, "invalid IPv4 address: %s", optarg);
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'j':
			threads = number("threads", optarg, 1,
			    CPU_SETSIZE - FIRST_CPU);
			break;
		case 'P':
			period_ms = number("period", optarg, 1, 3600000);
			break;
		case 't':
			seconds = number("seconds", optarg, 1, 86400);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (!strcmp(cmd, "flows") && argc == 1)
		flows(number("nflows", argv[0], 1, 65536 - FLOWS_PORT),
		    period_ms);
	else if (!strcmp(cmd, "pps") && argc == 0)
		pps(threads, seconds);
	else
		usage();

	return (0);
}
