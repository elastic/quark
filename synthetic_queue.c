// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "quark.h"

int	quark_process_cache_seed(struct quark_queue *, struct raw_event *);

static int	synthetic_queue_populate(struct quark_queue *);
static int	synthetic_queue_update_stats(struct quark_queue *);
static void	synthetic_queue_close(struct quark_queue *);
static int	synthetic_task_copy(struct quark_queue *, struct raw_task *,
		    const struct quark_synthetic_process *);

static struct quark_queue_ops queue_ops_synthetic = {
	.open		= synthetic_queue_open,
	.populate	= synthetic_queue_populate,
	.update_stats	= synthetic_queue_update_stats,
	.close		= synthetic_queue_close,
};

static int
synthetic_queue_populate(struct quark_queue *qq)
{
	return (0);
}

static int
synthetic_queue_update_stats(struct quark_queue *qq)
{
	return (0);
}

static void
synthetic_queue_close(struct quark_queue *qq)
{
}

int
synthetic_queue_open(struct quark_queue *qq)
{
	if ((qq->flags & QQ_SYNTHETIC) == 0)
		return (errno = EINVAL, -1);

	qq->queue_ops = &queue_ops_synthetic;
	qq->stats.backend = QQ_SYNTHETIC;

	return (0);
}

static int
synthetic_buffer_valid(const char *buf, size_t len)
{
	if (buf == NULL)
		return (len == 0);
	if (len == 0)
		return (0);

	return (buf[len - 1] == 0);
}

static char *
synthetic_strdup(const char *src)
{
	if (src == NULL)
		return (NULL);

	return (strdup(src));
}

/*
 * Seed the process cache from a synthetic file injection. RAW_FILE events
 * carry no raw_task in the union, so synthetic_task_copy() is never called
 * for them and raw_event_process1() never runs — leaving the cache empty for
 * a fresh pid, which makes raw_event_file() return qev->process == NULL.
 *
 * We build a scratch RAW_EXEC event, populate it via the same helpers used
 * for the normal inject path (synthetic_task_copy + exe/argv), then drive
 * raw_event_process1() against the cache entry directly, without inserting
 * the scratch event into the event tree. raw_event_process1() steals the
 * heap strings out of the scratch event, so raw_event_free() is safe to call
 * unconditionally at the end.
 */
static int
synthetic_process_seed(struct quark_queue *qq,
    const struct quark_synthetic_process *proc)
{
	struct raw_event	*seed;

	seed = raw_event_alloc(RAW_EXEC);
	if (seed == NULL)
		return (-1);
	seed->pid = proc->pid;
	seed->tid = proc->tid != 0 ? proc->tid : proc->pid;
	seed->exec.flags = RAW_EXEC_F_EXT;

	if (proc->executable != NULL) {
		seed->exec.filename = strdup(proc->executable);
		if (seed->exec.filename == NULL)
			goto fail;
	}
	if (proc->argv_len > 0 && proc->argv != NULL) {
		seed->exec.ext.args = malloc(proc->argv_len);
		if (seed->exec.ext.args == NULL)
			goto fail;
		memcpy(seed->exec.ext.args, proc->argv, proc->argv_len);
		seed->exec.ext.args_len = proc->argv_len;
	}
	if (synthetic_task_copy(qq, &seed->exec.ext.task, proc) == -1)
		goto fail;

	if (quark_process_cache_seed(qq, seed) == -1)
		goto fail;

	raw_event_free(seed);
	return (0);

fail:
	raw_event_free(seed);
	return (-1);
}

static int
synthetic_task_copy(struct quark_queue *qq, struct raw_task *dst,
    const struct quark_synthetic_process *src)
{
	size_t	env_len;

	dst->cap_inheritable = src->cap_inheritable;
	dst->cap_permitted = src->cap_permitted;
	dst->cap_effective = src->cap_effective;
	dst->cap_bset = src->cap_bset;
	dst->cap_ambient = src->cap_ambient;
	dst->start_boottime = src->start_boottime;
	dst->uid = src->uid;
	dst->gid = src->gid;
	dst->suid = src->suid;
	dst->sgid = src->sgid;
	dst->euid = src->euid;
	dst->egid = src->egid;
	dst->pgid = src->pgid;
	dst->sid = src->sid;
	dst->ppid = src->ppid;
	dst->exit_code = src->exit_code;
	dst->exit_time_event = src->exit_time_event;
	dst->tty_major = src->tty_major;
	dst->tty_minor = src->tty_minor;
	dst->uts_inonum = src->uts_inonum;
	dst->ipc_inonum = src->ipc_inonum;
	dst->mnt_inonum = src->mnt_inonum;
	dst->net_inonum = src->net_inonum;
	if (src->comm != NULL)
		strlcpy(dst->comm, src->comm, sizeof(dst->comm));

	if (src->cwd != NULL && (dst->cwd = synthetic_strdup(src->cwd)) == NULL)
		return (-1);
	if (src->cgroup != NULL &&
	    (dst->cgroup = synthetic_strdup(src->cgroup)) == NULL)
		return (-1);

	env_len = src->env_len;
	if (env_len > qq->max_env)
		env_len = qq->max_env;
	if (env_len > 0) {
		dst->env = malloc(env_len);
		if (dst->env == NULL)
			return (-1);
		memcpy(dst->env, src->env, env_len);
		dst->env[env_len - 1] = 0;
		dst->env_len = env_len;
	}

	return (0);
}

static int
synthetic_file_copy(struct raw_event *raw,
    const struct quark_synthetic_file *src, u32 op_mask)
{
	struct quark_file	*dst;
	size_t			 alloc_len, path_len, old_path_len;
	size_t			 sym_target_len;

	path_len = strlen(src->path) + 1;
	old_path_len = src->old_path == NULL ? 0 : strlen(src->old_path) + 1;
	sym_target_len = src->sym_target == NULL ?
	    0 : strlen(src->sym_target) + 1;
	alloc_len = sizeof(*dst);
	if (path_len > SIZE_MAX - alloc_len)
		return (errno = EOVERFLOW, -1);
	alloc_len += path_len;
	if (old_path_len > SIZE_MAX - alloc_len)
		return (errno = EOVERFLOW, -1);
	alloc_len += old_path_len;
	if (sym_target_len > SIZE_MAX - alloc_len)
		return (errno = EOVERFLOW, -1);
	alloc_len += sym_target_len;

	dst = calloc(1, alloc_len);
	if (dst == NULL)
		return (-1);
	raw->file.quark_file = dst;

	dst->path = dst->storage;
	memcpy((char *)dst->path, src->path, path_len);
	if (old_path_len > 0) {
		dst->old_path = dst->storage + path_len;
		memcpy((char *)dst->old_path, src->old_path, old_path_len);
	}
	if (sym_target_len > 0) {
		dst->sym_target = dst->storage + path_len + old_path_len;
		memcpy((char *)dst->sym_target, src->sym_target,
		    sym_target_len);
	}
	dst->inode = src->inode;
	dst->atime = src->atime;
	dst->mtime = src->mtime;
	dst->ctime = src->ctime;
	dst->size = src->size;
	dst->mode = src->mode;
	dst->uid = src->uid;
	dst->gid = src->gid;
	dst->op_mask = op_mask;
	dst->change_mask = src->change_mask;

	return (0);
}

int
quark_queue_inject(struct quark_queue *qq,
    const struct quark_synthetic_event *event)
{
	const struct quark_synthetic_process	*proc;
	struct raw_event			*raw;
	struct raw_task			*task;
	u32					 op_mask;
	int					 raw_type;

	if (qq == NULL || event == NULL || qq->queue_ops != &queue_ops_synthetic ||
	    qq->stats.backend != QQ_SYNTHETIC)
		return (errno = EINVAL, -1);

	proc = &event->process;
	if (event->time == 0 || proc->pid == 0 ||
	    !synthetic_buffer_valid(proc->argv, proc->argv_len) ||
	    !synthetic_buffer_valid(proc->env, proc->env_len))
		return (errno = EINVAL, -1);

	op_mask = 0;
	switch (event->kind) {
	case QUARK_SYNTHETIC_FORK:
		raw_type = RAW_WAKE_UP_NEW_TASK;
		break;
	case QUARK_SYNTHETIC_EXEC:
		if (proc->executable == NULL || proc->executable[0] == 0)
			return (errno = EINVAL, -1);
		raw_type = RAW_EXEC;
		break;
	case QUARK_SYNTHETIC_EXIT:
		raw_type = RAW_EXIT_THREAD;
		break;
	case QUARK_SYNTHETIC_SETSID:
		raw_type = RAW_ID_CHANGE;
		break;
	case QUARK_SYNTHETIC_FILE_CREATE:
		raw_type = RAW_FILE;
		op_mask = QUARK_FILE_OP_CREATE;
		break;
	case QUARK_SYNTHETIC_FILE_MODIFY:
		raw_type = RAW_FILE;
		op_mask = QUARK_FILE_OP_MODIFY;
		break;
	case QUARK_SYNTHETIC_FILE_DELETE:
		raw_type = RAW_FILE;
		op_mask = QUARK_FILE_OP_REMOVE;
		break;
	default:
		return (errno = EINVAL, -1);
	}
	if (raw_type == RAW_FILE &&
	    (event->file.path == NULL || event->file.path[0] == 0))
		return (errno = EINVAL, -1);

	raw = raw_event_alloc(raw_type);
	if (raw == NULL)
		return (-1);
	raw->pid = proc->pid;
	raw->tid = proc->tid == 0 ? proc->pid : proc->tid;
	raw->time = event->time;
	task = NULL;

	switch (raw_type) {
	case RAW_EXEC:
		raw->exec.flags = RAW_EXEC_F_EXT;
		raw->exec.filename = strdup(proc->executable);
		if (raw->exec.filename == NULL)
			goto fail;
		if (proc->argv_len > 0) {
			raw->exec.ext.args = malloc(proc->argv_len);
			if (raw->exec.ext.args == NULL)
				goto fail;
			memcpy(raw->exec.ext.args, proc->argv, proc->argv_len);
			raw->exec.ext.args_len = proc->argv_len;
		}
		task = &raw->exec.ext.task;
		break;
	case RAW_FILE:
		if (synthetic_file_copy(raw, &event->file, op_mask) == -1)
			goto fail;
		if (synthetic_process_seed(qq, proc) == -1)
			goto fail;
		break;
	case RAW_ID_CHANGE:
		raw->task.id_change = QUARK_ID_CHANGE_SETSID;
		task = &raw->task;
		break;
	case RAW_WAKE_UP_NEW_TASK: /* FALLTHROUGH */
	case RAW_EXIT_THREAD:
		task = &raw->task;
		break;
	default:
		goto inval;
	}

	if (task != NULL && synthetic_task_copy(qq, task, proc) == -1)
		goto fail;
	if (raw_type == RAW_EXIT_THREAD && task->exit_time_event == 0)
		task->exit_time_event = raw->time;

	if (raw_event_insert(qq, raw) == -1) {
		errno = EEXIST;
		goto fail;
	}

	return (0);

inval:
	errno = EINVAL;
fail:
	raw_event_free(raw);
	return (-1);
}
