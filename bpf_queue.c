// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <sys/epoll.h>
#include <sys/sysinfo.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "quark.h"
#include "bpf_prog_skel.h"
#include "elastic-ebpf/GPL/Events/EbpfEventProto.h"

struct bpf_queue {
	struct bpf_prog		*prog;
	struct ring_buffer	*ringbuf;
};

static int	bpf_queue_populate(struct quark_queue *);
static int	bpf_queue_update_stats(struct quark_queue *);
static void	bpf_queue_close(struct quark_queue *);

struct quark_queue_ops queue_ops_bpf = {
	.open	      = bpf_queue_open,
	.populate     = bpf_queue_populate,
	.update_stats = bpf_queue_update_stats,
	.close	      = bpf_queue_close,
};

/*
 * Map libbpf logs into quark_verbose.
 * fmt has a newline, we have to prepend program_invocatin_short_name, so we
 * can't use vwarn, as it prepends itself and adds a newline.
 */
static int
libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	int	 pri;
	char	*nfmt;

	if (level == LIBBPF_WARN || level == LIBBPF_INFO)
		pri = QUARK_VL_WARN;
	else if (level == LIBBPF_DEBUG)
		pri = QUARK_VL_DEBUG;
	else
		pri = QUARK_VL_WARN; /* fallback in case they add something new */

	if (pri > quark_verbose)
		return (0);

	/* best effort in out of mem situations */
	if (asprintf(&nfmt, "%s: %s", program_invocation_short_name, fmt) == -1)
		vfprintf(stderr, fmt, ap);
	else {
		vfprintf(stderr, nfmt, ap);
		free(nfmt);
	}

	return (0);
}

struct ebpf_ctx {
	struct ebpf_pid_info		*pids;
	struct ebpf_cred_info		*creds;
	struct ebpf_tty_dev		*ctty;
	char				*comm;
	struct ebpf_namespace_info	*ns;
	char				*cwd;
};

static void
ebpf_ctx_to_task(struct ebpf_ctx *ebpf_ctx, struct raw_task *task)
{
	task->cap_inheritable = 0; /* unavailable */
	task->cap_permitted = ebpf_ctx->creds->cap_permitted;
	task->cap_effective = ebpf_ctx->creds->cap_effective;
	task->cap_bset = 0; /* unavailable */
	task->cap_ambient = 0; /* unavailable */
	task->start_boottime = ebpf_ctx->pids->start_time_ns; /* XXX check format */
	task->uid = ebpf_ctx->creds->ruid;
	task->gid = ebpf_ctx->creds->rgid;
	task->suid = ebpf_ctx->creds->suid;
	task->sgid = ebpf_ctx->creds->sgid;
	task->euid = ebpf_ctx->creds->euid;
	task->egid = ebpf_ctx->creds->egid;
	task->pgid = ebpf_ctx->pids->pgid;
	task->sid = ebpf_ctx->pids->sid;
	task->ppid = ebpf_ctx->pids->ppid;
	/* skip exit_* */
	task->tty_major = ebpf_ctx->ctty->major;
	task->tty_minor = ebpf_ctx->ctty->minor;
	task->uts_inonum = ebpf_ctx->ns->uts_inonum;
	task->ipc_inonum = ebpf_ctx->ns->ipc_inonum;
	task->mnt_inonum = ebpf_ctx->ns->mnt_inonum;
	task->net_inonum = ebpf_ctx->ns->net_inonum;
	if (ebpf_ctx->cwd != NULL)
		qstr_strcpy(&task->cwd, ebpf_ctx->cwd);
	else
		qstr_strcpy(&task->cwd, "(invalid)");
	strlcpy(task->comm, ebpf_ctx->comm, sizeof(task->comm));
}

static struct raw_event *
ebpf_events_to_raw(struct ebpf_event_header *ev)
{
	struct raw_event		*raw;
	struct ebpf_process_fork_event	*fork;
	struct ebpf_process_exit_event	*exit;
	struct ebpf_process_exec_event	*exec;
	struct ebpf_varlen_field	*field;
	struct ebpf_ctx			 ebpf_ctx;

	bzero(&ebpf_ctx, sizeof(ebpf_ctx));
	raw = NULL;

	switch (ev->type) {
	case EBPF_EVENT_PROCESS_FORK:
		fork = (struct ebpf_process_fork_event *)ev;
		if (fork->child_pids.tid != fork->child_pids.tgid)
			goto bad;
		if ((raw = raw_event_alloc(RAW_WAKE_UP_NEW_TASK)) == NULL)
			goto bad;
		raw->pid = fork->child_pids.tid;
		raw->time = ev->ts;
		ebpf_ctx.pids = &fork->child_pids;
		ebpf_ctx.creds = &fork->creds;
		ebpf_ctx.ctty = &fork->ctty;
		ebpf_ctx.comm = fork->comm;
		ebpf_ctx.ns = &fork->ns;
		ebpf_ctx.cwd = NULL;
		/* the macro doesn't take a pointer so we can't pass down :) */
		FOR_EACH_VARLEN_FIELD(fork->vl_fields, field) {
			switch (field->type) {
			case EBPF_VL_FIELD_CWD:
				ebpf_ctx.cwd = field->data;
				break;
			default:
				break;
			}
		}
		ebpf_ctx_to_task(&ebpf_ctx, &raw->task);

		break;
	case EBPF_EVENT_PROCESS_EXIT:
		exit = (struct ebpf_process_exit_event *)ev;
		if (exit->pids.tid != exit->pids.tgid)
			goto bad;
		if ((raw = raw_event_alloc(RAW_EXIT_THREAD)) == NULL)
			goto bad;
		raw->pid = exit->pids.tid;
		raw->time = ev->ts;
		ebpf_ctx.pids = &exit->pids;
		ebpf_ctx.creds = &exit->creds;
		ebpf_ctx.ctty = &exit->ctty;
		ebpf_ctx.comm = exit->comm;
		ebpf_ctx.ns = &exit->ns;
		ebpf_ctx.cwd = NULL;
		raw->task.exit_code = exit->exit_code;
		raw->task.exit_time_event = raw->time;
		ebpf_ctx_to_task(&ebpf_ctx, &raw->task);

		break;
	case EBPF_EVENT_PROCESS_EXEC:
		exec = (struct ebpf_process_exec_event *)ev;
		if ((raw = raw_event_alloc(RAW_EXEC)) == NULL)
			goto bad;
		raw->pid = exec->pids.tid;
		raw->time = ev->ts;
		raw->exec.flags |= RAW_EXEC_F_EXT;
		ebpf_ctx.pids = &exec->pids;
		ebpf_ctx.creds = &exec->creds;
		ebpf_ctx.ctty = &exec->ctty;
		ebpf_ctx.comm = exec->comm;
		ebpf_ctx.ns = &exec->ns;
		ebpf_ctx.cwd = NULL;

		FOR_EACH_VARLEN_FIELD(exec->vl_fields, field) {
			switch (field->type) {
			case EBPF_VL_FIELD_CWD:
				ebpf_ctx.cwd = field->data;
				break;
			case EBPF_VL_FIELD_FILENAME:
				qstr_strcpy(&raw->exec.filename, field->data);
				break;
			case EBPF_VL_FIELD_ARGV:
				if (field->size == 0)
					raw->exec.ext.args.p[0] = 0;
				else {
					qstr_memcpy(&raw->exec.ext.args, field->data,
					    field->size);
					raw->exec.ext.args.p[field->size - 1] = 0;
					raw->exec.ext.args_len = field->size;
				}
				break;
			default:
				break;
			}
		}
		ebpf_ctx_to_task(&ebpf_ctx, &raw->exec.ext.task);

		break;
	default:
		qwarnx("unhandled type %lu", ev->type);
		goto bad;
	}

	return (raw);

bad:
	if (raw != NULL)
		raw_event_free(raw);

	return (NULL);
}

static int
bpf_ringbuf_cb(void *vqq, void *vdata, size_t len)
{
	struct quark_queue		*qq = vqq;
	struct ebpf_event_header	*ev = vdata;
	struct raw_event		*raw;

	raw = ebpf_events_to_raw(ev);
	if (raw != NULL && raw_event_insert(qq, raw) == -1)
		raw_event_free(raw);

	return (0);
}

int
bpf_queue_open(struct quark_queue *qq)
{
	struct bpf_queue	*bqq;
	struct ring_buffer_opts	 ringbuf_opts;
	struct bpf_program	*bp;
	int			 error;

	libbpf_set_print(libbpf_print_fn);

	if ((qq->flags & QQ_EBPF) == 0)
		return (errno = ENOTSUP, -1);

	if ((bqq = calloc(1, sizeof(*bqq))) == NULL)
		return (-1);

	qq->queue_be = bqq;

	bqq->prog = bpf_prog__open();
	if (bqq->prog == NULL) {
		qwarn("bpf_prog__open");
		goto fail;
	}

	/*
	 * Unload everything since it has way more than we want
	 */
	bpf_object__for_each_program(bp, bqq->prog->obj)
		bpf_program__set_autoload(bp, 0);
	/*
	 * Load just the bits we want
	 */
	bpf_program__set_autoload(bqq->prog->progs.sched_process_fork, 1);
	bpf_program__set_autoload(bqq->prog->progs.sched_process_exec, 1);
	bpf_program__set_autoload(bqq->prog->progs.kprobe__taskstats_exit, 1);

	error = bpf_map__set_max_entries(bqq->prog->maps.event_buffer_map,
	    get_nprocs_conf());
	if (error != 0) {
		qwarn("bpf_map__set_max_entries");
		goto fail;
	}

	error = bpf_prog__load(bqq->prog);
	if (error) {
		qwarn("bpf_prog__load");
		goto fail;
	}

	error = bpf_prog__attach(bqq->prog);
	if (error) {
		qwarn("bpf_prog__attach");
		goto fail;
	}

	/*
	 * There doesn't seem to be a watermark setting for ebpf!
	 */
	ringbuf_opts.sz = sizeof(ringbuf_opts);
	bqq->ringbuf = ring_buffer__new(bpf_map__fd(bqq->prog->maps.ringbuf),
	    bpf_ringbuf_cb, qq, &ringbuf_opts);
	if (bqq->ringbuf == NULL) {
		qwarn("ring_buffer__new");
		goto fail;
	}

	qq->epollfd = ring_buffer__epoll_fd(bqq->ringbuf);
	if (qq->epollfd < 0)
		goto fail;

	qq->queue_ops = &queue_ops_bpf;
	qq->stats.backend = QQ_EBPF;

	return (0);
fail:
	bpf_queue_close(qq);

	return (-1);
}

static int
bpf_queue_populate(struct quark_queue *qq)
{
	struct bpf_queue	*bqq = qq->queue_be;
	int			 npop, space_left;

	space_left = qq->length >= qq->max_length ?
	    0 : qq->max_length - qq->length;
	if (space_left == 0)
		return (0);

	npop = ring_buffer__consume_n(bqq->ringbuf, space_left);

	return (npop < 0 ? -1 : npop);
}

static int
bpf_queue_update_stats(struct quark_queue *qq)
{
	struct bpf_queue	*bqq  = qq->queue_be;
	struct ebpf_event_stats	 pcpu_ees[libbpf_num_possible_cpus()];
	u32			 zero = 0;
	int			 i;

	/* valgrind doesn't track that this will be updated below */
	bzero(pcpu_ees, sizeof(pcpu_ees));

	if (bpf_map__lookup_elem(bqq->prog->maps.ringbuf_stats, &zero,
	    sizeof(zero), pcpu_ees, sizeof(pcpu_ees), 0) != 0)
		return (-1);

	for (i = 0; i < libbpf_num_possible_cpus(); i++)
		qq->stats.lost = pcpu_ees[i].lost;

	return (0);
}

static void
bpf_queue_close(struct quark_queue *qq)
{
	struct bpf_queue	*bqq = qq->queue_be;

	if (bqq != NULL) {
		if (bqq->prog != NULL) {
			bpf_prog__destroy(bqq->prog);
			bqq->prog = NULL;
		}
		if (bqq->ringbuf != NULL) {
			ring_buffer__free(bqq->ringbuf);
			bqq->ringbuf = NULL;
		}
		free(bqq);
		bqq = NULL;
		qq->queue_be = NULL;
	}
	/* Closed in ring_buffer__free() */
	qq->epollfd = -1;
}
