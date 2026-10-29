// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "quark.h"

static u64
boottime_ns(void)
{
	struct timespec ts;

	assert(clock_gettime(CLOCK_BOOTTIME, &ts) == 0);
	return (TS_TO_NS(ts));
}

static void
synthetic_attr(struct quark_queue_attr *attr)
{
	quark_queue_default_attr(attr);
	attr->flags &= ~(QQ_EBPF | QQ_KPROBE | QQ_NOVA);
	attr->flags |= QQ_SYNTHETIC | QQ_FILE;
	attr->hold_time = 0;
	attr->cache_grace_time = 0;
}

static struct quark_synthetic_process
synthetic_process(u32 pid, u32 ppid)
{
	static const char argv[] = "some-program\0--config\0/etc/app.yml\0";
	static const char env[] = "HOME=/opt/app\0PATH=/usr/local/bin:/usr/bin\0";
	struct quark_synthetic_process proc;

	bzero(&proc, sizeof(proc));
	proc.pid = pid;
	proc.tid = pid;
	proc.ppid = ppid;
	proc.pgid = ppid == 0 ? pid : ppid;
	proc.sid = ppid == 0 ? pid : ppid;
	proc.start_boottime = boottime_ns() - 1000000;
	proc.uid = 1000;
	proc.gid = 1000;
	proc.suid = 1000;
	proc.sgid = 1000;
	proc.euid = 1000;
	proc.egid = 1000;
	proc.cap_permitted = 1ULL << 10;
	proc.cap_effective = 1ULL << 10;
	proc.tty_major = 136;
	proc.tty_minor = 2;
	proc.uts_inonum = 4026531838;
	proc.ipc_inonum = 4026531839;
	proc.mnt_inonum = 4026531840;
	proc.net_inonum = 4026531841;
	proc.comm = "some-program";
	proc.cwd = "/opt/app";
	proc.cgroup = "/kubepods.slice/test.scope";
	proc.argv = argv;
	proc.argv_len = sizeof(argv);
	proc.env = env;
	proc.env_len = sizeof(env);
	proc.executable = "/usr/local/bin/some-program";

	return (proc);
}

static struct quark_synthetic_event
synthetic_event(enum quark_synthetic_event_kind kind, u32 pid, u32 ppid,
    u64 time)
{
	struct quark_synthetic_event event;

	bzero(&event, sizeof(event));
	event.kind = kind;
	event.time = time;
	event.process = synthetic_process(pid, ppid);

	return (event);
}

static size_t
process_count(struct quark_queue *qq)
{
	struct quark_process_iter iter;
	size_t n;

	n = 0;
	quark_process_iter_init(&iter, qq);
	while (quark_process_iter_next(&iter) != NULL)
		n++;

	return (n);
}

static void
test_validation(void)
{
	struct quark_queue qq;
	struct quark_queue fake;
	struct quark_queue_attr attr;
	struct quark_synthetic_event event;
	char malformed[] = { 'x' };
	u64 now;

	quark_queue_default_attr(&attr);
	attr.hold_time = 0;
	errno = 0;
	assert(quark_queue_open(&qq, &attr) == -1);
	assert(errno == EINVAL);

	synthetic_attr(&attr);
	attr.hold_time = 1;
	errno = 0;
	assert(quark_queue_open(&qq, &attr) == -1);
	assert(errno == EINVAL);

	synthetic_attr(&attr);
	assert(quark_queue_open(&qq, &attr) == 0);
	now = boottime_ns() - 1000;
	event = synthetic_event(QUARK_SYNTHETIC_EXEC, 1000, 0, now);

	errno = 0;
	assert(quark_queue_inject(NULL, &event) == -1 && errno == EINVAL);
	errno = 0;
	assert(quark_queue_inject(&qq, NULL) == -1 && errno == EINVAL);

	event.kind = QUARK_SYNTHETIC_INVALID;
	errno = 0;
	assert(quark_queue_inject(&qq, &event) == -1 && errno == EINVAL);
	event.kind = QUARK_SYNTHETIC_EXEC;
	event.time = 0;
	errno = 0;
	assert(quark_queue_inject(&qq, &event) == -1 && errno == EINVAL);
	event.time = now;
	event.process.pid = 0;
	errno = 0;
	assert(quark_queue_inject(&qq, &event) == -1 && errno == EINVAL);
	event.process.pid = 1000;
	event.process.executable = NULL;
	errno = 0;
	assert(quark_queue_inject(&qq, &event) == -1 && errno == EINVAL);
	event.process.executable = "/bin/test";
	event.process.argv = malformed;
	event.process.argv_len = sizeof(malformed);
	errno = 0;
	assert(quark_queue_inject(&qq, &event) == -1 && errno == EINVAL);

	event = synthetic_event(QUARK_SYNTHETIC_FILE_CREATE, 1000, 0, now);
	event.file.path = NULL;
	errno = 0;
	assert(quark_queue_inject(&qq, &event) == -1 && errno == EINVAL);

	bzero(&fake, sizeof(fake));
	fake.flags = QQ_EBPF;
	event = synthetic_event(QUARK_SYNTHETIC_FORK, 1000, 0, now);
	errno = 0;
	assert(quark_queue_inject(&fake, &event) == -1 && errno == EINVAL);

	quark_queue_close(&qq);
}

static void
test_lifecycle_file_cache_and_stats(void)
{
	struct quark_queue qq;
	struct quark_queue_attr attr;
	struct quark_queue_stats stats;
	struct quark_synthetic_event event;
	const struct quark_event *qev;
	const struct quark_process *proc;
	char executable[] = "/usr/local/bin/some-program";
	char cwd[] = "/opt/app";
	u64 now;

	synthetic_attr(&attr);
	assert(quark_queue_open(&qq, &attr) == 0);
	assert(process_count(&qq) == 0);
	quark_queue_get_stats(&qq, &stats);
	assert(stats.backend == QQ_SYNTHETIC);
	assert(stats.insertions == 0);

	now = boottime_ns() - 10000;
	event = synthetic_event(QUARK_SYNTHETIC_EXEC, 1000, 0, now++);
	event.process.executable = executable;
	event.process.cwd = cwd;
	assert(quark_queue_inject(&qq, &event) == 0);
	memset(executable, 'x', strlen(executable));
	memset(cwd, 'x', strlen(cwd));
	qev = quark_queue_get_event(&qq);
	assert(qev != NULL && qev->events == QUARK_EV_EXEC);
	assert(qev->process != NULL);
	assert(strcmp(qev->process->exe, "/usr/local/bin/some-program") == 0);
	assert(strcmp(qev->process->cwd, "/opt/app") == 0);
	assert(strcmp(qev->process->cgroup, "/kubepods.slice/test.scope") == 0);
	assert(qev->process->cmdline_len > 0);
	assert(qev->process->env_len > 0);

	event = synthetic_event(QUARK_SYNTHETIC_FORK, 1001, 1000, now++);
	assert(quark_queue_inject(&qq, &event) == 0);
	qev = quark_queue_get_event(&qq);
	assert(qev != NULL && qev->events == QUARK_EV_FORK);
	assert(qev->process != NULL);
	assert(strcmp(qev->process->exe, "/usr/local/bin/some-program") == 0);
	assert(qev->process->cmdline_len > 0);

	event = synthetic_event(QUARK_SYNTHETIC_FORK, 1002, 1000, now++);
	assert(quark_queue_inject(&qq, &event) == 0);
	event = synthetic_event(QUARK_SYNTHETIC_EXEC, 1002, 1000, now++);
	assert(quark_queue_inject(&qq, &event) == 0);
	event = synthetic_event(QUARK_SYNTHETIC_SETSID, 1002, 1000, now++);
	event.process.sid = 1002;
	event.process.pgid = 1002;
	assert(quark_queue_inject(&qq, &event) == 0);
	event = synthetic_event(QUARK_SYNTHETIC_EXIT, 1002, 1000, now++);
	event.process.exit_code = 23;
	event.process.sid = 1002;
	event.process.pgid = 1002;
	assert(quark_queue_inject(&qq, &event) == 0);
	qev = quark_queue_get_event(&qq);
	assert(qev != NULL);
	assert(qev->events ==
	    (QUARK_EV_FORK | QUARK_EV_EXEC | QUARK_EV_ID_CHANGE |
	    QUARK_EV_EXIT));
	assert(qev->id_change == QUARK_ID_CHANGE_SETSID);
	assert(qev->process->exit_code == 23);
	assert(qev->process->proc_sid == 1002);
	assert(quark_queue_get_event(&qq) == NULL);
	assert(quark_process_lookup(&qq, 1002) == NULL);
	assert(errno == ESRCH);

	event = synthetic_event(QUARK_SYNTHETIC_FILE_CREATE, 1000, 0, now++);
	event.file.path = "/var/log/app/output.log";
	event.file.inode = 42;
	event.file.mode = 0100644;
	event.file.uid = 1000;
	event.file.gid = 1000;
	assert(quark_queue_inject(&qq, &event) == 0);
	event.kind = QUARK_SYNTHETIC_FILE_MODIFY;
	event.time = now++;
	event.file.change_mask = QUARK_FILE_CH_CONTENT;
	assert(quark_queue_inject(&qq, &event) == 0);
	event.kind = QUARK_SYNTHETIC_FILE_DELETE;
	event.time = now++;
	assert(quark_queue_inject(&qq, &event) == 0);
	qev = quark_queue_get_event(&qq);
	assert(qev != NULL && qev->events == QUARK_EV_FILE);
	assert(qev->process != NULL && qev->process->pid == 1000);
	assert(qev->file != NULL && strcmp(qev->file->path,
	    "/var/log/app/output.log") == 0);
	assert(qev->file->op_mask == (QUARK_FILE_OP_CREATE |
	    QUARK_FILE_OP_MODIFY | QUARK_FILE_OP_REMOVE));
	assert(qev->file->change_mask == QUARK_FILE_CH_CONTENT);
	assert(quark_queue_get_event(&qq) == NULL);

	proc = quark_process_lookup(&qq, 1000);
	assert(proc != NULL && strcmp(proc->exe,
	    "/usr/local/bin/some-program") == 0);
	assert(process_count(&qq) == 2);
	quark_queue_get_stats(&qq, &stats);
	assert(stats.backend == QQ_SYNTHETIC);
	assert(stats.insertions == 9);
	assert(stats.removals == 9);
	assert(stats.aggregations == 2);
	assert(stats.garbage_collections == 1);

	quark_queue_close(&qq);
}

/*
 * raw_event_insert() moves an event to the next free timestamp when the one
 * it asks for is taken, so the time an event ends up with is only known after
 * the insert. Check that an exit reports the same value in its event time and
 * in exit_time_event even when it was moved. Also check that a run of taken
 * timestamps long enough to exhaust the walk reports EEXIST.
 */
static void
test_timestamp_collision(void)
{
	struct quark_queue qq;
	struct quark_queue_attr attr;
	struct quark_synthetic_event event;
	const struct quark_event *qev;
	u64 collide_at;
	int i;

	synthetic_attr(&attr);
	assert(quark_queue_open(&qq, &attr) == 0);

	collide_at = boottime_ns() - 100000;

	/* Take the timestamp with an unrelated pid, so the exit has to move. */
	event = synthetic_event(QUARK_SYNTHETIC_EXEC, 7001, 0, collide_at);
	assert(quark_queue_inject(&qq, &event) == 0);

	event = synthetic_event(QUARK_SYNTHETIC_EXIT, 7002, 0, collide_at);
	event.process.exit_code = 23;
	assert(quark_queue_inject(&qq, &event) == 0);

	qev = quark_queue_get_event(&qq);
	assert(qev != NULL && qev->process->pid == 7001);
	assert(qev->time == collide_at);

	qev = quark_queue_get_event(&qq);
	assert(qev != NULL && qev->process->pid == 7002);
	assert(qev->events == QUARK_EV_EXIT);
	assert(qev->process->exit_code == 23);
	/* Moved off the taken slot, and exit_time_event went with it. */
	assert(qev->time == collide_at + 1);
	assert(qev->process->exit_time_event == qev->time);

	quark_queue_close(&qq);

	/* A fully taken run of a thousand timestamps exhausts the walk. */
	synthetic_attr(&attr);
	assert(quark_queue_open(&qq, &attr) == 0);

	collide_at = boottime_ns() - 100000;
	for (i = 0; i < 1000; i++) {
		event = synthetic_event(QUARK_SYNTHETIC_EXEC, 8000 + i, 0,
		    collide_at + i);
		assert(quark_queue_inject(&qq, &event) == 0);
	}
	event = synthetic_event(QUARK_SYNTHETIC_EXEC, 9999, 0, collide_at);
	errno = 0;
	assert(quark_queue_inject(&qq, &event) == -1 && errno == EEXIST);

	/* One past the run is still free. */
	event = synthetic_event(QUARK_SYNTHETIC_EXEC, 9999, 0,
	    collide_at + 1000);
	assert(quark_queue_inject(&qq, &event) == 0);

	quark_queue_close(&qq);
}

static void
ruleset_from_string(struct quark_ruleset *ruleset, const char *text)
{
	char errbuf[1024];
	FILE *f;

	quark_ruleset_init(ruleset);
	f = fmemopen((void *)text, strlen(text), "r");
	assert(f != NULL);
	assert(quark_ruleset_parse(ruleset, f, errbuf, sizeof(errbuf)) == 0);
	fclose(f);
}

static void
test_rules(void)
{
	struct quark_queue qq;
	struct quark_queue_attr attr;
	struct quark_ruleset ruleset;
	struct quark_synthetic_event event;
	const struct quark_event *qev;
	u64 now;

	ruleset_from_string(&ruleset,
	    "pass on process.exe /usr/local/bin/some-program\n"
	    "pass on file.path /var/log/app/output.log\n"
	    "drop on any\n");
	synthetic_attr(&attr);
	attr.ruleset = &ruleset;
	assert(quark_queue_open(&qq, &attr) == 0);
	now = boottime_ns() - 10000;

	event = synthetic_event(QUARK_SYNTHETIC_EXEC, 1000, 0, now++);
	assert(quark_queue_inject(&qq, &event) == 0);
	qev = quark_queue_get_event(&qq);
	assert(qev != NULL && qev->events == QUARK_EV_EXEC);

	event = synthetic_event(QUARK_SYNTHETIC_FILE_CREATE, 1000, 0, now++);
	event.file.path = "/var/log/app/output.log";
	event.file.inode = 42;
	assert(quark_queue_inject(&qq, &event) == 0);
	qev = quark_queue_get_event(&qq);
	assert(qev != NULL && qev->events == QUARK_EV_FILE);

	event = synthetic_event(QUARK_SYNTHETIC_EXEC, 1001, 1000, now++);
	event.process.executable = "/usr/bin/unwanted";
	assert(quark_queue_inject(&qq, &event) == 0);
	assert(quark_queue_get_event(&qq) == NULL);

	quark_queue_close(&qq);
	quark_ruleset_clear(&ruleset);
}

int
main(void)
{
	test_validation();
	test_lifecycle_file_cache_and_stats();
	test_timestamp_collision();
	test_rules();
	puts("synthetic queue tests passed");

	return (0);
}
