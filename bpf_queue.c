// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <sys/epoll.h>
#include <sys/param.h>
#include <sys/sysinfo.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
	struct ebpf_varlen_field	*field;
	struct ebpf_ctx			 ebpf_ctx;

	bzero(&ebpf_ctx, sizeof(ebpf_ctx));
	raw = NULL;

	switch (ev->type) {
	case EBPF_EVENT_PROCESS_FORK: {
		struct ebpf_process_fork_event	*fork;

		fork = (struct ebpf_process_fork_event *)ev;
		if ((raw = raw_event_alloc(RAW_WAKE_UP_NEW_TASK)) == NULL)
			goto bad;
		raw->pid = fork->child_pids.tgid;
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
	}
	case EBPF_EVENT_PROCESS_EXIT: {
		struct ebpf_process_exit_event	*exit;

		exit = (struct ebpf_process_exit_event *)ev;
		if ((raw = raw_event_alloc(RAW_EXIT_THREAD)) == NULL)
			goto bad;
		raw->pid = exit->pids.tgid;
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
	}
	case EBPF_EVENT_PROCESS_EXEC: {
		struct ebpf_process_exec_event	*exec;

		exec = (struct ebpf_process_exec_event *)ev;
		if ((raw = raw_event_alloc(RAW_EXEC)) == NULL)
			goto bad;
		raw->pid = exec->pids.tgid;
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
	}
	case EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED:
	case EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED:
	case EBPF_EVENT_NETWORK_CONNECTION_CLOSED: {
		struct ebpf_net_event	*net;
		struct raw_sock_conn	*conn;

		net = (struct ebpf_net_event *)ev;
		if ((raw = raw_event_alloc(RAW_SOCK_CONN)) == NULL)
			goto bad;

		raw->pid = net->pids.tgid;
		raw->time = ev->ts;
		conn = &raw->sock_conn;

		if (net->net.family == EBPF_NETWORK_EVENT_AF_INET) {
			conn->local.af = AF_INET;
			memcpy(&conn->local.addr4, net->net.saddr, 4);

			conn->remote.af = AF_INET;
			memcpy(&conn->remote.addr4, net->net.daddr, 4);
		} else if (net->net.family == EBPF_NETWORK_EVENT_AF_INET6) {
			conn->local.af = AF_INET6;
			memcpy(conn->local.addr6, net->net.saddr6, 16);

			conn->remote.af = AF_INET6;
			memcpy(conn->remote.addr6, net->net.daddr6, 16);
		} else
			goto bad;

		conn->local.port = htons(net->net.sport);
		conn->remote.port = htons(net->net.dport);

		switch (ev->type) {
		case EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED:
			raw->sock_conn.conn = SOCK_CONN_ACCEPT;
			break;
		case EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED:
			raw->sock_conn.conn = SOCK_CONN_CONNECT;
			break;
		case EBPF_EVENT_NETWORK_CONNECTION_CLOSED:
			raw->sock_conn.conn = SOCK_CONN_CLOSE;
			break;
		default:
			goto bad;
		}

		break;
	}
	case EBPF_EVENT_NETWORK_DNS_PKT: {
		struct ebpf_dns_event	*dns;
		size_t			 cap_len;
		struct quark_packet	*packet;

		dns = (struct ebpf_dns_event *)ev;
		if ((raw = raw_event_alloc(RAW_PACKET)) == NULL)
			goto bad;
		raw->pid = dns->tgid;
		raw->time = ev->ts;

		cap_len = MIN(dns->cap_len, QUARK_MAX_PACKET);
		raw->packet.quark_packet = calloc(1, sizeof(*raw->packet.quark_packet) + cap_len);
		if (raw->packet.quark_packet == NULL)
			goto bad;
		packet = raw->packet.quark_packet;

		switch (dns->direction) {
		case EBPF_NETWORK_DIR_EGRESS:
			packet->direction = QUARK_PACKET_DIR_EGRESS;
			break;
		case EBPF_NETWORK_DIR_INGRESS:
			packet->direction = QUARK_PACKET_DIR_INGRESS;
			break;
		default:
			goto bad;
		}

		packet->origin = QUARK_PACKET_ORIGIN_DNS;
		packet->orig_len = dns->orig_len;
		packet->cap_len = cap_len;

		FOR_EACH_VARLEN_FIELD(dns->vl_fields, field) {
			switch (field->type) {
			case EBPF_VL_FIELD_DNS_BODY:
				memcpy(packet->data, field->data, cap_len);
				break;
			default:
				goto bad;
			}
		}
		break;
	}
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
	struct bpf_prog		*p;
	struct ring_buffer_opts	 ringbuf_opts;
	struct bpf_program	*bp;
	int			 cgroup_fd;

	libbpf_set_print(libbpf_print_fn);

	if ((qq->flags & QQ_EBPF) == 0)
		return (errno = ENOTSUP, -1);

	if ((bqq = calloc(1, sizeof(*bqq))) == NULL)
		return (-1);

	qq->queue_be = bqq;
	cgroup_fd = -1;

	bqq->prog = bpf_prog__open();
	if (bqq->prog == NULL) {
		qwarn("bpf_prog__open");
		goto fail;
	}
	p = bqq->prog;

	/*
	 * Unload everything since it has way more than we want
	 */
	bpf_object__for_each_program(bp, p->obj)
		bpf_program__set_autoload(bp, 0);
	/*
	 * Load just the bits we want
	 */
	bpf_program__set_autoload(p->progs.sched_process_fork, 1);
	bpf_program__set_autoload(p->progs.sched_process_exec, 1);
	bpf_program__set_autoload(p->progs.sched_process_exit, 1);
	bpf_program__set_autoload(p->progs.kprobe__taskstats_exit, 1);

	if (qq->flags & QQ_SOCK_CONN) {
		bpf_program__set_autoload(p->progs.kretprobe__inet_csk_accept, 1);

		bpf_program__set_autoload(p->progs.kprobe__tcp_v4_connect, 1);
		bpf_program__set_autoload(p->progs.kretprobe__tcp_v4_connect, 1);

		bpf_program__set_autoload(p->progs.kprobe__tcp_v6_connect, 1);
		bpf_program__set_autoload(p->progs.kretprobe__tcp_v6_connect, 1);

		bpf_program__set_autoload(p->progs.kprobe__tcp_close, 1);
	}

	if (qq->flags & QQ_DNS) {
		cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
		if (cgroup_fd == -1) {
			qwarn("open cgroup");
			goto fail;
		}
		bpf_program__set_autoload(p->progs.skb_egress, 1);
		bpf_program__set_autoload(p->progs.skb_ingress, 1);
		bpf_program__set_autoload(p->progs.sock_create, 1);
		bpf_program__set_autoload(p->progs.sock_release, 1);
		bpf_program__set_autoload(p->progs.sendmsg4, 1);
		bpf_program__set_autoload(p->progs.connect4, 1);
		bpf_program__set_autoload(p->progs.recvmsg4, 1);
	}

	if (bpf_map__set_max_entries(p->maps.event_buffer_map,
	    get_nprocs_conf()) != 0) {
		qwarn("bpf_map__set_max_entries");
		goto fail;
	}

	if (bpf_prog__load(p) != 0) {
		qwarn("bpf_prog__load");
		goto fail;
	}

	if (bpf_prog__attach(p) != 0) {
		qwarn("bpf_prog__attach");
		goto fail;
	}

#define CG_ATTACH_OR_FAIL(_program, _error)				\
	if (bpf_program__attach_cgroup(p->progs._program,		\
	    cgroup_fd) == NULL) {					\
	    qwarn(_error);						\
	    goto fail;							\
	}

	if (cgroup_fd != -1) {
		CG_ATTACH_OR_FAIL(skb_egress, "attach skb_egress");
		CG_ATTACH_OR_FAIL(skb_ingress, "attach skb_ingress");
		CG_ATTACH_OR_FAIL(sock_create, "attach sock_create");
		CG_ATTACH_OR_FAIL(sock_release, "attach sock_release");
		CG_ATTACH_OR_FAIL(sendmsg4, "attach sendmsg4");
		CG_ATTACH_OR_FAIL(connect4, "attach connect4");
		CG_ATTACH_OR_FAIL(recvmsg4, "attach recvmsg4");

		close(cgroup_fd);
		cgroup_fd = -1;
	}
#undef ATTACH_OR_FAIL

	/*
	 * There doesn't seem to be a watermark setting for ebpf!
	 */
	ringbuf_opts.sz = sizeof(ringbuf_opts);
	bqq->ringbuf = ring_buffer__new(bpf_map__fd(p->maps.ringbuf),
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
	if (cgroup_fd != -1) {
		close(cgroup_fd);
		cgroup_fd = -1;
	}

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
