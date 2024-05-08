#include <sys/epoll.h>
#include <sys/sysinfo.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "quark.h"
#include "bpf_prog_skel.h"
#include "elastic-ebpf/GPL/Events/EbpfEventProto.h"

static int	bpf_queue_populate(struct quark_queue *);
static int	bpf_queue_block(struct quark_queue *);
static void	bpf_queue_close(struct quark_queue *);

struct quark_queue_ops queue_ops_bpf = {
	.open	  = bpf_queue_open,
	.populate = bpf_queue_populate,
	.block	  = bpf_queue_block,
	.close	  = bpf_queue_close,
};

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (quark_verbose >= 2)
		return vfprintf(stderr, format, args);

	return (0);
}

static const char *
ebpf_events_type_to_str(u64 type)
{
	switch (type) {
	case EBPF_EVENT_PROCESS_FORK:
		return "EBPF_EVENT_PROCESS_FORK";
	case EBPF_EVENT_PROCESS_EXEC:
		return "EBPF_EVENT_PROCESS_EXEC";
	case EBPF_EVENT_PROCESS_EXIT:
		return "EBPF_EVENT_PROCESS_EXIT";
	case EBPF_EVENT_PROCESS_SETSID:
		return "EBPF_EVENT_PROCESS_SETSID";
	case EBPF_EVENT_PROCESS_SETUID:
		return "EBPF_EVENT_PROCESS_SETUID";
	case EBPF_EVENT_PROCESS_SETGID:
		return "EBPF_EVENT_PROCESS_SETGID";
	default:
		return "unknown";
	}
}

static void
ebpf_events_to_task(struct ebpf_pid_info *pids, struct ebpf_cred_info *creds,
    struct raw_task *task, u32 *pid)
{
	*pid = pids->tid;
	task->ppid = pids->pgid;
	task->start_boottime = pids->start_time_ns; /* XXX check format */
	task->cap_inheritable = 0; /* unavailable */
	task->cap_permitted = creds->cap_permitted;
	task->cap_effective = creds->cap_effective;
	task->cap_bset = 0; /* unavailable */
	task->cap_ambient = 0; /* unavailable */
	task->uid = creds->ruid;
	task->gid = creds->rgid;
	task->suid = creds->suid;
	task->sgid = creds->sgid;
	task->euid = creds->euid;
	task->egid = creds->egid;
	task->exit_code = -1;
	task->exit_time_event = 0;
	qstr_init(&task->cwd);
}

static struct raw_event *
ebpf_events_to_raw(struct ebpf_event_header *ev)
{
	struct raw_event		*raw;
	struct ebpf_process_fork_event	*fork;
	struct ebpf_process_exit_event	*exit;
	struct ebpf_process_exec_event	*exec;
	struct ebpf_varlen_field	*field;

	raw = NULL;

	switch (ev->type) {
	case EBPF_EVENT_PROCESS_FORK: /* FALLTHROUGH */
	case EBPF_EVENT_PROCESS_EXIT: /* FALLTHROUGH */
	case EBPF_EVENT_PROCESS_EXEC:
		if ((raw = raw_event_alloc()) == NULL)
			goto bad;
		raw->time = ev->ts;
		break;
	default:
		warnx("%s:%d unhandled type %s\n", __func__, __LINE__,
		    ebpf_events_type_to_str(ev->type));
		goto bad;
	}

	switch (ev->type) {
	case EBPF_EVENT_PROCESS_FORK:
		fork = (struct ebpf_process_fork_event *)ev;
		if (fork->child_pids.tid != fork->child_pids.tgid)
			goto bad;
		raw->type = RAW_WAKE_UP_NEW_TASK;
		ebpf_events_to_task(&fork->child_pids, &fork->creds,
		    &raw->task, &raw->pid);
		/* the macro doesn't take a pointer so we can't pass down :) */
		FOR_EACH_VARLEN_FIELD(fork->vl_fields, field) {
			switch (field->type) {
			case EBPF_VL_FIELD_CWD:
				qstr_strcpy(&raw->task.cwd, field->data);
				break;
			default:
				break;
			}
		}
		break;
	case EBPF_EVENT_PROCESS_EXIT:
		exit = (struct ebpf_process_exit_event *)ev;
		raw->type = RAW_EXIT_THREAD;
		if (exit->pids.tid != exit->pids.tgid)
			goto bad;
		ebpf_events_to_task(&exit->pids, &exit->creds,
		    &raw->task, &raw->pid);
		raw->task.exit_code = exit->exit_code;
		raw->task.exit_time_event = raw->time;
		/* the macro doesn't take a pointer so we can't pass down :) */
		FOR_EACH_VARLEN_FIELD(exit->vl_fields, field) {
			switch (field->type) {
			case EBPF_VL_FIELD_CWD:
				qstr_strcpy(&raw->task.cwd, field->data);
				break;
			default:
				break;
			}
		}
		break;
	case EBPF_EVENT_PROCESS_EXEC:
		exec = (struct ebpf_process_exec_event *)ev;
		raw->type = RAW_EXEC;
		raw->exec.flags |= RAW_EXEC_F_EXT;
		ebpf_events_to_task(&exec->pids, &exec->creds,
		    &raw->exec.ext.task, &raw->pid);
		qstr_init(&raw->exec.filename);
		qstr_init(&raw->exec.ext.args);
		qstr_init(&raw->exec.ext.task.cwd);
		strlcpy(raw->exec.ext.comm, exec->comm,
		    sizeof(raw->exec.ext.comm));
		FOR_EACH_VARLEN_FIELD(exec->vl_fields, field) {
			switch (field->type) {
			case EBPF_VL_FIELD_CWD:
				qstr_strcpy(&raw->exec.ext.task.cwd, field->data);
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
		break;
	default:
		warnx("%s:%d\n unhandled type %s\n", __func__, __LINE__,
		    ebpf_events_type_to_str(ev->type));
		goto bad;
	}

	return (raw);

bad:
	/* XXX redo raw_event_alloc pass the type and init all qstr */
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
	if (raw != NULL)
		raw_event_insert(qq, raw);

	return (0);
}

int
bpf_queue_open(struct quark_queue *qq)
{
	struct ring_buffer	*ringbuf;
	struct ring_buffer_opts	 ringbuf_opts;
	struct bpf_prog		*bpf_prog;
	struct bpf_program	*bp;
	int			 error;

	if ((qq->flags & QQ_EBPF) == 0)
		return (errno = ENOTSUP, -1);

	libbpf_set_print(libbpf_print_fn);

	bpf_prog = bpf_prog__open();
	if (bpf_prog == NULL) {
		warn("bpf_prog__open");
		return (-1);
	}

	/*
	 * Unload everything since it has way more than we want
	 */
	bpf_object__for_each_program(bp, bpf_prog->obj)
		bpf_program__set_autoload(bp, 0);
	/*
	 * Load just the bits we want
	 */
	bpf_program__set_autoload(bpf_prog->progs.sched_process_fork, 1);
	bpf_program__set_autoload(bpf_prog->progs.sched_process_exec, 1);
	bpf_program__set_autoload(bpf_prog->progs.kprobe__taskstats_exit, 1);

	error = bpf_map__set_max_entries(bpf_prog->maps.event_buffer_map,
	    get_nprocs_conf());
	if (error != 0) {
		warn("bpf_map__set_max_entries");
		goto fail;
	}

	error = bpf_prog__load(bpf_prog);
	if (error) {
		warn("bpf_prog__load");
		goto fail;
	}

	error = bpf_prog__attach(bpf_prog);
	if (error) {
		warn("bpf_prog__attach");
		goto fail;
	}

	/*
	 * There doesn't seem to be a watermark setting for ebpf!
	 */
	ringbuf_opts.sz = sizeof(ringbuf_opts);
	ringbuf = ring_buffer__new(bpf_map__fd(bpf_prog->maps.ringbuf),
	    bpf_ringbuf_cb, qq, &ringbuf_opts);
	if (ringbuf == NULL) {
		warn("ring_buffer__new");
		goto fail;
	}

	qq->bpf_prog = bpf_prog;
	qq->ringbuf = ringbuf;
	qq->queue_ops = &queue_ops_bpf;

	return (0);
fail:
	bpf_prog__destroy(bpf_prog);
	return (-1);
}

static int
bpf_queue_populate(struct quark_queue *qq)
{
	int	npop, space_left;

	npop = 0;
	space_left = qq->length >= qq->max_length ?
	    0 : qq->max_length - qq->length;
	if (space_left == 0)
		return (0);

	npop = ring_buffer__consume_n(qq->ringbuf, space_left);

	return (npop < 0 ? -1 : npop);
}

static int
bpf_queue_block(struct quark_queue *qq)
{
	int			fd;
	struct epoll_event	ev;

	fd = ring_buffer__epoll_fd(qq->ringbuf);
	if (fd < 0)
		return (-1);

	if (epoll_wait(fd, &ev, 1, 100) == -1)
		return (-1);

	return (0);
}

static void
bpf_queue_close(struct quark_queue *qq)
{
	if (qq->bpf_prog) {
		bpf_prog__destroy(qq->bpf_prog);
		qq->bpf_prog = NULL;
	}
	if (qq->ringbuf) {
		ring_buffer__free(qq->ringbuf);
		qq->ringbuf = NULL;
	}
}