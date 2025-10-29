// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <sys/epoll.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/sysinfo.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/btf.h>

#include "quark.h"
#include "bpf_probes_skel.h"
#include "elastic-ebpf/GPL/Events/EbpfEventProto.h"

struct bpf_queue {
	struct bpf_probes	*probes;
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

/*
 * This structure exists to work around the bad layout of ebpf events
 */
struct ebpf_ctx {
	struct ebpf_pid_info		*pids;
	struct ebpf_cred_info		*creds;
	struct ebpf_tty_dev		*ctty;
	char				*comm;
	struct ebpf_namespace_info	*ns;
	char				*cwd;
	char				*cgroup;
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
		task->cwd = strdup(ebpf_ctx->cwd);
	if (ebpf_ctx->cgroup != NULL)
		task->cgroup = strdup(ebpf_ctx->cgroup);
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
		ebpf_ctx.cgroup = NULL;
		/* the macro doesn't take a pointer so we can't pass down :) */
		FOR_EACH_VARLEN_FIELD(fork->vl_fields, field) {
			switch (field->type) {
			case EBPF_VL_FIELD_CWD:
				ebpf_ctx.cwd = field->data;
				break;
			case EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH:
				if (field->size > 0 && *field->data != 0)
					ebpf_ctx.cgroup = field->data;
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
		ebpf_ctx.cgroup = NULL;

		FOR_EACH_VARLEN_FIELD(exit->vl_fields, field) {
			switch (field->type) {
			case EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH:
				if (field->size > 0 && *field->data != 0)
					ebpf_ctx.cgroup = field->data;
				break;
			default:
				break;
			}
		}

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
		ebpf_ctx.cgroup = NULL;

		FOR_EACH_VARLEN_FIELD(exec->vl_fields, field) {
			switch (field->type) {
			case EBPF_VL_FIELD_CWD:
				ebpf_ctx.cwd = field->data;
				break;
			case EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH:
				if (field->size > 0 && *field->data != 0)
					ebpf_ctx.cgroup = field->data;
				break;
			case EBPF_VL_FIELD_FILENAME:
				raw->exec.filename = strdup(field->data);
				/* filename might still be NULL */
				break;
			case EBPF_VL_FIELD_ARGV:
				if (field->size == 0)
					break;
				raw->exec.ext.args = malloc(field->size);
				if (raw->exec.ext.args == NULL)
					break;
				raw->exec.ext.args_len = field->size;
				memcpy(raw->exec.ext.args, field->data,
				    field->size);
				raw->exec.ext.args[field->size - 1] = 0;
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
			raw->sock_conn.bytes_received = net->net.tcp.close.bytes_received;
			raw->sock_conn.bytes_sent = net->net.tcp.close.bytes_sent;
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
				qwarnx("unhandled field type %d", field->type);
				goto bad;
			}
		}
		break;
	}
	case EBPF_EVENT_FILE_SHMEM_OPEN:
		goto drop;
		break;
	case EBPF_EVENT_FILE_CREATE: /* FALLTHROUGH */
	case EBPF_EVENT_FILE_DELETE: /* FALLTHROUGH */
	case EBPF_EVENT_FILE_MODIFY: /* FALLTHROUGH */
	case EBPF_EVENT_FILE_RENAME: {
		struct ebpf_file_info		*info;
		const char			*path, *old_path, *sym_target;
		struct ebpf_varlen_fields_start *vl;
		size_t				 path_len, sym_target_len, old_path_len;
		size_t				 alloc_len, tmp_len;
		struct quark_file		*file;
		u32				 op_mask, dummy;

		if ((raw = raw_event_alloc(RAW_FILE)) == NULL)
			goto bad;

		raw->time = ev->ts;

		/*
		 * Cope with the weird ebpf layout structures
		 */
		info = NULL;
		vl = NULL;
		op_mask = 0;
		switch (ev->type) {
		case EBPF_EVENT_FILE_CREATE: {
			struct ebpf_file_create_event *create =
			    (struct ebpf_file_create_event *)ev;
			info = &create->finfo;
			vl = &create->vl_fields;
			raw->pid = create->pids.tgid;
			op_mask = QUARK_FILE_OP_CREATE;
			break;
		}
		case EBPF_EVENT_FILE_DELETE: {
			struct ebpf_file_delete_event *delete =
			    (struct ebpf_file_delete_event *)ev;
			info = &delete->finfo;
			vl = &delete->vl_fields;
			raw->pid = delete->pids.tgid;
			op_mask = QUARK_FILE_OP_REMOVE;
			break;
		}
		case EBPF_EVENT_FILE_MODIFY: {
			struct ebpf_file_modify_event *modify =
			    (struct ebpf_file_modify_event *)ev;
			info = &modify->finfo;
			vl = &modify->vl_fields;
			raw->pid = modify->pids.tgid;
			op_mask = QUARK_FILE_OP_MODIFY;
			break;
		}
		case EBPF_EVENT_FILE_RENAME: {
			struct ebpf_file_rename_event *rename =
			    (struct ebpf_file_rename_event *)ev;
			info = &rename->finfo;
			vl = &rename->vl_fields;
			raw->pid = rename->pids.tgid;
			op_mask = QUARK_FILE_OP_MOVE;
			break;
		}
		default:
			qwarnx("unhandled file event type %lu", ev->type);
			goto bad;
		}

		if (info == NULL) {
			qwarnx("no info");
			goto bad;
		}

		path = old_path = sym_target = NULL;
		path_len = old_path_len = sym_target_len = tmp_len = 0;

		FOR_EACH_VARLEN_FIELD_PTR(vl, field, dummy) {
			switch (field->type) {
			case EBPF_VL_FIELD_PATH:	/* FALLTHROUGH */
			case EBPF_VL_FIELD_NEW_PATH:
				tmp_len = strlen(field->data);
				if (tmp_len > 0) {
					path = field->data;
					path_len = tmp_len + 1; /* with NUL */
				}
				break;
			case EBPF_VL_FIELD_SYMLINK_TARGET_PATH:
				tmp_len = strlen(field->data);
				if (tmp_len > 0) {
					sym_target = field->data;
					sym_target_len = tmp_len + 1; /* with NUL */
				}
				break;
			case EBPF_VL_FIELD_OLD_PATH:
				tmp_len = strlen(field->data);
				if (tmp_len > 0) {
					old_path = field->data;
					old_path_len = tmp_len + 1; /* with NUL */
				}
				continue;
			case EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH: /* ignored */
				break;
			default:
				qwarnx("unhandled field type %d", field->type);
				goto bad;
			}
		}

		if (path == NULL) {
			qwarnx("no path");
			goto bad;
		}

		/*
		 * Calculate allocation length, it is the size of the structure
		 * plus enough storage for all the 3 paths, path + old_path +
		 * sym_target. The paths all reside in storage and we point to
		 * their offsets, this way we have just one block allocation
		 * from ring_buffer all the way up to the user, and we don't
		 * have to manage memory for it.
		 */
		alloc_len = sizeof(*raw->file.quark_file);
		alloc_len += path_len;
		if (old_path != NULL)
			alloc_len += old_path_len; /* NUL already in old_path_len */
		if (sym_target != NULL)
			alloc_len += sym_target_len; /* NUL already in sym_target_len */
		alloc_len++;			     /* extra NUL for paranoia */

		raw->file.quark_file = calloc(1, alloc_len);
		if (raw->file.quark_file == NULL)
			goto bad;
		file = raw->file.quark_file;
		file->path = file->storage;
		memcpy((char *)file->path, path, path_len);
		if (old_path && old_path_len > 0) {
			file->old_path = file->storage + path_len;
			memcpy((char *)file->old_path, old_path, old_path_len);
		}
		if (sym_target && sym_target_len > 0) {
			file->sym_target = file->storage + path_len +
			    old_path_len;
			memcpy((char *)file->sym_target, sym_target, sym_target_len);
		}

		file->inode = info->inode;
		file->atime = info->atime;
		file->mtime = info->mtime;
		file->ctime = info->ctime;
		file->size = info->size;
		file->mode = info->mode;
		file->uid = info->uid;
		file->gid = info->gid;
		file->op_mask = op_mask;

		break;
	}
	default:
		qwarnx("unhandled type %lu", ev->type);
		goto bad;
	}

	return (raw);

drop:
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
	struct quark_event		*qev;
	struct raw_event		*raw;

	if (qq->flags & QQ_BYPASS) {
		qev = &qq->event_storage;
		qev->bypass = ev;
		qev->events = QUARK_EV_BYPASS;
	} else {
		raw = ebpf_events_to_raw(ev);
		if (raw != NULL && raw_event_insert(qq, raw) == -1)
			raw_event_free(raw);
	}

	return (0);
}

/*
 * Lookup where cgroup2 is mounted, if it's not, try to mount it ourselves, if
 * so, fill unmount_path with the temporary cgroup2 path that must be unmounted
 * by calling cgroup2_umount_tmp().
 */
static void
cgroup2_umount_tmp(char **path)
{
	if (path == NULL || *path == NULL)
		return;
	if (umount(*path) == -1)
		qwarn("can't umount temporary cgroup2 at %s, "
		    "mount point will dangle!", *path);
	else if (rmdir(*path) == -1)
		qwarn("can't unlink temporary cgroup2 at %s, "
		    "directory will dangle!", *path);
	free(*path);
	*path = NULL;
}

static int
cgroup2_open_fd(char **umount_path)
{
	char	*save_line, *file_buf;
	char	*line, *start, *end, *path;
	int	 fd;

	fd = -1;
	path = NULL;
	*umount_path = NULL;

	if ((file_buf = load_file_path_nostat("/proc/mounts", NULL)) == NULL) {
		qwarn("load_file_path_nostat /proc/mounts");
		goto fail;
	}

	for (line = strtok_r(file_buf, "\n", &save_line);
	     line != NULL;
	     line = strtok_r(NULL, "\n", &save_line)) {
		if (strncasecmp(line, "cgroup2", strlen("cgroup2")))
			continue;
		if ((start = strchr(line, ' ')) == NULL) {
			qwarn("no space 1");
			continue;
		}
		start++;
		if ((end = strchr(start, ' ')) == NULL) {
			qwarn("no space 2");
			continue;
		}
		path = strndup(start, end - start);
		break;
	}
	free(file_buf);

	/*
	 * No cgroup2 mount found, try to mount it ourselves at
	 * /tmp/quark_cgroup2_mount.XXXXX.
	 * If we succeed, we must pass the mounting point up to the caller, so
	 * it can umount after the probes are loaded.
	 */
	if (path == NULL) {
		char template[] = "/tmp/quark_cgroup2_mount.XXXXXX";

		if ((path = mkdtemp(template)) == NULL) {
			qwarn("mkdtemp %s", template);
			goto fail;
		}
		qwarnx("no cgroup2 mount found, will try mounting it "
		    "ourselves at %s", path);

		path = strdup(path);
		if (path == NULL) {
			qwarn("strdup");
			goto fail;
		}
		if (mount(NULL, path, "cgroup2", 0, NULL) == -1) {
			qwarn("mount %s", path);
			goto fail;
		}

		if ((*umount_path = strdup(path)) == NULL) {
			qwarn("strdup");
			goto fail;
		}
	}

	if (path == NULL) {
		qwarnx("no cgroup2 mount");
		goto fail;
	}

	if ((fd = open(path, O_RDONLY)) == -1) {
		qwarn("open %s", path);
		goto fail;
	}
	free(path);

	return (fd);

fail:
	free(path);
	if (fd != -1)
		close(fd);
	cgroup2_umount_tmp(umount_path);

	return (-1);
}

static int
relo_ret(struct btf *btf, int *loc, const char *func)
{
	*loc = btf_number_of_params(btf, func);
	if (*loc == -1)
		qwarnx("can't relocate return for %s", func);

	return (*loc);
}

static int
relo_param(struct btf *btf, int *loc, const char *func, const char *param)
{
	*loc = btf_index_of_param(btf, func, param);
	if (*loc == -1)
		qwarnx("can't relocate parameter %s on function %s",
		    param, func);

	return (*loc);
}

static int
relo_member(struct btf *btf, int *loc, const char *struct_name,
    const char *member)
{
	char dotname[512];

	*loc = -1;

	if (snprintf(dotname, sizeof(dotname), "%s.%s", struct_name, member)
	    >= (int)sizeof(dotname)) {
		qwarnx("buffer too small");
		return (-1);
	}

	*loc = btf_root_offset(btf, dotname, 0);

	return (*loc);
}

static struct bpf_probes *
open_probes(void)
{
	struct bpf_object_open_opts	 opts, *op;
	const char			*custom_path;

	op = NULL;
	if ((custom_path = getenv("QUARK_BTF_PATH")) != NULL) {
		bzero(&opts, sizeof(opts));
		opts.sz = sizeof(opts);
		opts.btf_custom_path = custom_path;
		op = &opts;
	}

	return (bpf_probes__open_opts(op));
}

static int
bpf_queue_open1(struct quark_queue *qq, int use_fentry)
{
	struct bpf_queue		*bqq;
	struct bpf_probes		*p;
	struct ring_buffer_opts		 ringbuf_opts;
	int				 cgroup_fd, i, off, ringbuf_fd;
	char				*cgroup_umount;
	struct bpf_prog_skeleton	*ps;
	struct btf			*btf;
	struct epoll_event		 ev;

	libbpf_set_print(libbpf_print_fn);

	if ((bqq = calloc(1, sizeof(*bqq))) == NULL)
		return (-1);

	qq->queue_be = bqq;
	cgroup_fd = -1;
	cgroup_umount = NULL;
	btf = NULL;

	bqq->probes = open_probes();
	if (bqq->probes == NULL) {
		qwarn("bpf_probes__open");
		goto fail;
	}
	p = bqq->probes;

	/*
	 * BTF used for relocations
	 */
	btf = btf__load_vmlinux_btf();
	if (btf == NULL) {
		qwarn("btf__load_vmlinux_btf");
		goto fail;
	}

	/*
	 * Maps and other state
	 */
	p->rodata->consumer_pid = getpid();

	/*
	 * Unload everything since it has way more than we want
	 */
	for (i = 0; i < p->skeleton->prog_cnt; i++) {
		ps = &p->skeleton->progs[i];
		bpf_program__set_autoload(*ps->prog, 0);
	}

	/*
	 * Load just the bits we want
	 */
	bpf_program__set_autoload(p->progs.sched_process_fork, 1);
	bpf_program__set_autoload(p->progs.sched_process_exec, 1);

	if (use_fentry)
		bpf_program__set_autoload(p->progs.fentry__disassociate_ctty, 1);
	else
		bpf_program__set_autoload(p->progs.kprobe__disassociate_ctty, 1);

	/* Used in process probes, so always on */
	if (relo_member(btf, &off, "iov_iter", "__iov") != -1)
		p->rodata->off__iov_iter____iov__ = off;

	if (qq->flags & QQ_SOCK_CONN) {
		if (use_fentry) {
			bpf_program__set_autoload(p->progs.fexit__inet_csk_accept, 1);
			bpf_program__set_autoload(p->progs.fexit__tcp_v4_connect, 1);
			if (ipv6_supported())
				bpf_program__set_autoload(p->progs.fexit__tcp_v6_connect, 1);
			bpf_program__set_autoload(p->progs.fentry__tcp_close, 1);
		} else {
			bpf_program__set_autoload(p->progs.kretprobe__inet_csk_accept, 1);
			bpf_program__set_autoload(p->progs.kprobe__tcp_v4_connect, 1);
			bpf_program__set_autoload(p->progs.kretprobe__tcp_v4_connect, 1);
			if (ipv6_supported()) {
				bpf_program__set_autoload(p->progs.kprobe__tcp_v6_connect, 1);
				bpf_program__set_autoload(p->progs.kretprobe__tcp_v6_connect, 1);
			}
			bpf_program__set_autoload(p->progs.kprobe__tcp_close, 1);
		}

		if (relo_ret(btf, &p->rodata->ret__inet_csk_accept__,
		    "inet_csk_accept") == -1)
			goto fail;
	}

	if (qq->flags & QQ_FILE) {
		int use_fsnotify =
		    (btf_number_of_params_of_ptr(btf, "inode_operations", "atomic_open") == 6);

		if (use_fentry) {
			bpf_program__set_autoload(p->progs.fentry__do_renameat2, 1);
			bpf_program__set_autoload(p->progs.fentry__do_unlinkat, 1);
			if (use_fsnotify)
				bpf_program__set_autoload(p->progs.fentry__fsnotify, 1);
			bpf_program__set_autoload(p->progs.fentry__mnt_want_write, 1);
			bpf_program__set_autoload(p->progs.fentry__vfs_rename, 1);
			bpf_program__set_autoload(p->progs.fentry__vfs_unlink, 1);
			bpf_program__set_autoload(p->progs.fexit__chmod_common, 1);
			bpf_program__set_autoload(p->progs.fexit__chown_common, 1);
			bpf_program__set_autoload(p->progs.fexit__do_filp_open, 1);
			bpf_program__set_autoload(p->progs.fexit__do_truncate, 1);
			bpf_program__set_autoload(p->progs.fexit__vfs_rename, 1);
			bpf_program__set_autoload(p->progs.fexit__vfs_unlink, 1);
			bpf_program__set_autoload(p->progs.fexit__vfs_write, 1);
			bpf_program__set_autoload(p->progs.fexit__vfs_writev, 1);
		} else {
			bpf_program__set_autoload(p->progs.kprobe__chmod_common, 1);
			bpf_program__set_autoload(p->progs.kretprobe__chmod_common, 1);
			bpf_program__set_autoload(p->progs.kprobe__chown_common, 1);
			bpf_program__set_autoload(p->progs.kretprobe__chown_common, 1);
			bpf_program__set_autoload(p->progs.kprobe__do_truncate, 1);
			bpf_program__set_autoload(p->progs.kretprobe__do_truncate, 1);
			if (use_fsnotify)
				bpf_program__set_autoload(p->progs.kprobe__fsnotify, 1);
			bpf_program__set_autoload(p->progs.kprobe__vfs_writev, 1);
			bpf_program__set_autoload(p->progs.kretprobe__vfs_writev, 1);
			bpf_program__set_autoload(p->progs.kprobe__vfs_rename, 1);
			bpf_program__set_autoload(p->progs.kretprobe__vfs_rename, 1);
			bpf_program__set_autoload(p->progs.kprobe__vfs_unlink, 1);
			bpf_program__set_autoload(p->progs.kretprobe__vfs_unlink, 1);
			bpf_program__set_autoload(p->progs.kprobe__vfs_write, 1);
			bpf_program__set_autoload(p->progs.kretprobe__vfs_write, 1);
			bpf_program__set_autoload(p->progs.kprobe__do_renameat2, 1);
			bpf_program__set_autoload(p->progs.kprobe__do_unlinkat, 1);
			bpf_program__set_autoload(p->progs.kprobe__mnt_want_write, 1);
			bpf_program__set_autoload(p->progs.kretprobe__do_filp_open, 1);
		}

		/* vfs_unlink() */
		if (relo_ret(btf, &p->rodata->ret__vfs_unlink__, "vfs_unlink") == -1)
			goto fail;
		if (relo_param(btf, &p->rodata->arg__vfs_unlink__dentry__,
		    "vfs_unlink", "dentry") == -1)
			goto fail;
		/* vfs_rename() */
		if (relo_ret(btf, &p->rodata->ret__vfs_rename__, "vfs_rename") == -1)
			goto fail;
		if (btf_index_of_param(btf, "vfs_rename", "rd") != -1) {
			p->rodata->exists__vfs_rename__rd__ = 1;
		} else {
			if (relo_param(btf, &p->rodata->arg__vfs_rename__old_dentry__,
			    "vfs_rename", "old_dentry") == -1)
				goto fail;
			if (relo_param(btf, &p->rodata->arg__vfs_rename__new_dentry__,
			    "vfs_rename", "new_dentry") == -1)
				goto fail;
		}
		/* do_truncate() */
		if (relo_ret(btf, &p->rodata->ret__do_truncate__, "do_truncate") == -1)
			goto fail;
		if (relo_param(btf, &p->rodata->arg__do_truncate__filp__,
		    "do_truncate", "filp") == -1)
			goto fail;
	}

	if (qq->flags & QQ_DNS) {
		cgroup_fd = cgroup2_open_fd(&cgroup_umount);
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

	if (qq->flags & QQ_MEMFD) {
		bpf_program__set_autoload(p->progs.tracepoint_syscalls_sys_enter_memfd_create, 1);
		bpf_program__set_autoload(p->progs.tracepoint_syscalls_sys_enter_shmget, 1);
		bpf_program__set_autoload(p->progs.module_load, 1);
		bpf_program__set_autoload(p->progs.kprobe__ptrace_attach, 1);
		bpf_program__set_autoload(p->progs.kprobe__arch_ptrace, 1);
	}

	if (qq->flags & QQ_TTY) {
		if (use_fentry)
			bpf_program__set_autoload(p->progs.fentry__tty_write, 1);
		else
			bpf_program__set_autoload(p->progs.kprobe__tty_write, 1);
	}

	/*
	 * These are probes that are not attached to a feature and not currently
	 * used in quark, but we need to maintain compatibility in BYPASS.
	 */
	if (qq->flags & QQ_BYPASS) {
		bpf_program__set_autoload(p->progs.tracepoint_syscalls_sys_exit_setsid, 1);
	}

	if (bpf_map__set_max_entries(p->maps.event_buffer_map,
	    get_nprocs_conf()) != 0) {
		qwarn("bpf_map__set_max_entries");
		goto fail;
	}

	if (bpf_probes__load(p) != 0) {
		qwarn("bpf_probes__load");
		goto fail;
	}

	if (cgroup_fd != -1) {
		for (i = 0; i < p->skeleton->prog_cnt; i++) {
			ps = &p->skeleton->progs[i];

			switch (bpf_program__get_type(*ps->prog)) {
			case BPF_PROG_TYPE_CGROUP_DEVICE:	/* FALLTHROUGH */
			case BPF_PROG_TYPE_CGROUP_SKB:		/* FALLTHROUGH */
			case BPF_PROG_TYPE_CGROUP_SOCK:		/* FALLTHROUGH */
			case BPF_PROG_TYPE_CGROUP_SOCKOPT:	/* FALLTHROUGH */
			case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:	/* FALLTHROUGH */
			case BPF_PROG_TYPE_CGROUP_SYSCTL:
				break;
			default:
				continue;
			}

			*ps->link = bpf_program__attach_cgroup(*ps->prog,
			    cgroup_fd);
			if (*ps->link == NULL) {
				qwarn("bpf_program__attach_cgroup %s",
				    ps->name);
				goto fail;
			}
		}

		close(cgroup_fd);
		cgroup_fd = -1;
	}
	cgroup2_umount_tmp(&cgroup_umount);

	if (bpf_probes__attach(p) != 0) {
		qwarn("bpf_probes__attach");
		goto fail;
	}

	ringbuf_opts.sz = sizeof(ringbuf_opts);
	bqq->ringbuf = ring_buffer__new(bpf_map__fd(p->maps.ringbuf),
	    bpf_ringbuf_cb, qq, &ringbuf_opts);
	if (bqq->ringbuf == NULL) {
		qwarn("ring_buffer__new");
		goto fail;
	}

	ringbuf_fd = ring_buffer__epoll_fd(bqq->ringbuf);
	if (ringbuf_fd < 0) {
		qwarnx("ring_buffer__epoll_fd failed");
		goto fail;
	}
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = ringbuf_fd;
	if (epoll_ctl(qq->epollfd, EPOLL_CTL_ADD, ringbuf_fd, &ev) == -1) {
		qwarn("epoll_ctl");
		goto fail;
	}

	qq->queue_ops = &queue_ops_bpf;
	qq->stats.backend = QQ_EBPF;

	btf__free(btf);

	return (0);
fail:
	if (cgroup_fd != -1) {
		close(cgroup_fd);
		cgroup_fd = -1;
	}
	cgroup2_umount_tmp(&cgroup_umount);
	if (btf != NULL)
		btf__free(btf);

	bpf_queue_close(qq);

	return (-1);
}

int
bpf_queue_open(struct quark_queue *qq)
{
	if ((qq->flags & QQ_EBPF) == 0)
		return (errno = ENOTSUP, -1);

	if (bpf_queue_open1(qq, 1) == -1) {
		qwarn("bpf_queue_open failed with fentry, trying kprobe");
		return bpf_queue_open1(qq, 0);
	}

	return (0);
}

static int
bpf_queue_populate(struct quark_queue *qq)
{
	struct bpf_queue	*bqq = qq->queue_be;
	int			 npop, space_left;

	space_left =
	    qq->flags & QQ_BYPASS ? 1 :
	    qq->length >= qq->max_length ? 0 :
	    qq->max_length - qq->length;
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

	if (bpf_map__lookup_elem(bqq->probes->maps.ringbuf_stats, &zero,
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

	if (bqq == NULL)
		return;
	if (bqq->probes != NULL) {
		bpf_probes__destroy(bqq->probes);
		bqq->probes = NULL;
	}
	if (bqq->ringbuf != NULL) {
		int	ringbuf_fd;

		ringbuf_fd = ring_buffer__epoll_fd(bqq->ringbuf);
		if (ringbuf_fd >= 0) {
			if (epoll_ctl(qq->epollfd, EPOLL_CTL_DEL, ringbuf_fd,
			    NULL) == -1)
				qwarn("epoll_ctl EPOLL_CTL_DEL");
		}
		/* this closes ringbuf_fd! */
		ring_buffer__free(bqq->ringbuf);
		ringbuf_fd = -1;
		bqq->ringbuf = NULL;
	}
	free(bqq);
	bqq = NULL;
	qq->queue_be = NULL;
}

struct bpf_probes *
quark_get_bpf_probes(struct quark_queue *qq)
{
	struct bpf_queue *bqq = qq->queue_be;

	if (!(qq->flags & QQ_EBPF) || !(qq->flags & QQ_BYPASS))
		return (errno = EINVAL, NULL);

	return (bqq->probes);
}
