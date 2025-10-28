// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <sys/epoll.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <netpacket/packet.h>

#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <fts.h>
#include <grp.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <poll.h>
#include <pwd.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "quark.h"

#define AGE(_ts, _now) 		((_ts) > (_now) ? 0 : (_now) - (_ts))

static int	raw_event_by_time_cmp(struct raw_event *, struct raw_event *);
static int	raw_event_by_pidtime_cmp(struct raw_event *, struct raw_event *);
static int	process_by_pid_cmp(struct quark_process *, struct quark_process *);
static int	socket_by_src_dst_cmp(struct quark_socket *, struct quark_socket *);
static int	container_by_id_cmp(struct quark_container *, struct quark_container *);
static int	pod_by_uid_cmp(struct quark_pod *, struct quark_pod *);
static int	label_node_cmp(struct label_node *, struct label_node *);
static int	quark_passwd_cmp(struct quark_passwd *, struct quark_passwd *);
static int	quark_group_cmp(struct quark_group *, struct quark_group *);

static void	process_cache_delete(struct quark_queue *, struct quark_process *);
static void	socket_cache_delete(struct quark_queue *, struct quark_socket *);
static void	pod_delete(struct quark_queue *, struct quark_pod *);
static void	container_delete(struct quark_queue *, struct quark_container *);

/* For debugging */
int	quark_verbose;

RB_PROTOTYPE(process_by_pid, quark_process,
    entry_by_pid, process_by_pid_cmp);
RB_GENERATE(process_by_pid, quark_process,
    entry_by_pid, process_by_pid_cmp);

RB_PROTOTYPE(socket_by_src_dst, quark_socket,
    entry_by_src_dst, socket_by_src_dst_cmp);
RB_GENERATE(socket_by_src_dst, quark_socket,
    entry_by_src_dst, socket_by_src_dst_cmp);

RB_PROTOTYPE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);
RB_GENERATE(raw_event_by_time, raw_event,
    entry_by_time, raw_event_by_time_cmp);

RB_PROTOTYPE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);
RB_GENERATE(raw_event_by_pidtime, raw_event,
    entry_by_pidtime, raw_event_by_pidtime_cmp);

RB_PROTOTYPE(container_by_id, quark_container,
    entry_qkube, container_by_id_cmp);
RB_GENERATE(container_by_id, quark_container,
    entry_qkube, container_by_id_cmp);
RB_PROTOTYPE(pod_containers, quark_container,
    entry_pod, container_by_id_cmp);
RB_GENERATE(pod_containers, quark_container,
    entry_pod, container_by_id_cmp);

RB_PROTOTYPE(pod_by_uid, quark_pod, entry_by_uid, pod_by_uid_cmp);
RB_GENERATE(pod_by_uid, quark_pod, entry_by_uid, pod_by_uid_cmp);

RB_PROTOTYPE(label_tree, label_node, entry, label_node_cmp);
RB_GENERATE(label_tree, label_node, entry, label_node_cmp);

RB_PROTOTYPE(passwd_by_uid, quark_passwd, entry, quark_passwd_cmp);
RB_GENERATE(passwd_by_uid, quark_passwd, entry, quark_passwd_cmp);

RB_PROTOTYPE(group_by_gid, quark_group, entry, quark_group_cmp);
RB_GENERATE(group_by_gid, quark_group, entry, quark_group_cmp);

struct quark {
	unsigned int	hz;
	u64		boottime;
} quark;

struct raw_event *
raw_event_alloc(int type)
{
	struct raw_event *raw;

	if ((raw = calloc(1, sizeof(*raw))) == NULL)
		return (NULL);

	raw->type = type;
	TAILQ_INIT(&raw->agg_queue);

	switch (raw->type) {
	case RAW_WAKE_UP_NEW_TASK: /* FALLTHROUGH */
	case RAW_EXIT_THREAD:
		raw->task.exit_code = -1;
		break;
	case RAW_EXEC:		/* nada */
	case RAW_EXEC_CONNECTOR:/* nada */
	case RAW_COMM:		/* nada */
	case RAW_SOCK_CONN:	/* nada */
	case RAW_PACKET:	/* caller allocates */
	case RAW_FILE:		/* caller allocates */
	case RAW_PTRACE:	/* nada */
	case RAW_MODULE_LOAD:	/* caller allocates */
	case RAW_SHM:		/* caller allocates */
		break;
	default:
		qwarnx("unhandled raw_type %d", raw->type);
		free(raw);
		return (NULL);
	}

	return (raw);
}

void
raw_event_free(struct raw_event *raw)
{
	struct raw_event	*aux;
	struct raw_task		*task;

	task = NULL;
	switch (raw->type) {
	case RAW_WAKE_UP_NEW_TASK:
	case RAW_EXIT_THREAD:
		task = &raw->task;
		break;
	case RAW_EXEC:
		free(raw->exec.filename);
		free(raw->exec.ext.args);
		task = &raw->exec.ext.task;
		break;
	case RAW_EXEC_CONNECTOR:
		free(raw->exec_connector.args);
		task = &raw->exec_connector.task;
		break;
	case RAW_COMM:		/* nada */
	case RAW_SOCK_CONN:	/* nada */
	case RAW_PTRACE:	/* nada */
		break;
	case RAW_PACKET:
		free(raw->packet.quark_packet);
		break;
	case RAW_FILE:
		free(raw->file.quark_file);
		break;
	case RAW_MODULE_LOAD: {
		struct quark_module_load *qml;

		qml = raw->module_load.quark_module_load;
		if (qml == NULL)
			break;
		free(qml->name);
		free(qml->version);
		free(qml->src_version);
		free(qml);
		break;
	}
	case RAW_SHM:
		if (raw->shm.quark_shm != NULL) {
			free(raw->shm.quark_shm->path);
			free(raw->shm.quark_shm);
		}
		break;
	default:
		qwarnx("unhandled raw_type %d", raw->type);
		break;
	}

	if (task != NULL) {
		free(task->cwd);
		free(task->cgroup);
	}

	while ((aux = TAILQ_FIRST(&raw->agg_queue)) != NULL) {
		TAILQ_REMOVE(&raw->agg_queue, aux, agg_entry);
		raw_event_free(aux);
	}

	free(raw);
}

static int
raw_event_by_time_cmp(struct raw_event *a, struct raw_event *b)
{
	if (a->time < b->time)
		return (-1);
	else
		return (a->time > b->time);
}

static int
raw_event_by_pidtime_cmp(struct raw_event *a, struct raw_event *b)
{
	if (a->pid < b->pid)
		return (-1);
	else if (a->pid > b->pid)
		return (1);

	if (a->time < b->time)
		return (-1);
	else
		return (a->time > b->time);
}

static inline u64
now64(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		return (0);

	return ((u64)ts.tv_sec * (u64)NS_PER_S + (u64)ts.tv_nsec);
}

static inline u64
raw_event_age(struct raw_event *raw, u64 now)
{
	return AGE(raw->time, now);
}

/*
 * Target age is the duration in ns of how long should we hold the event in the
 * tree before processing it. It's a function of the number of items in the tree
 * and its maximum capacity:
 * from [0; 10%]    -> 1000ms
 * from [90%; 100%] -> 0ms
 * from (10%; 90%)  -> linear from 1000ms -> 100ms
 */
static u64
raw_event_target_age(struct quark_queue *qq)
{
	int	v;

	if (qq->length < (qq->max_length / 10))
		v = qq->hold_time;
	else if (qq->length < ((qq->max_length / 10) * 9)) {
		if (qq->max_length > qq->hold_time)
			v = qq->hold_time -
			    (qq->length / (qq->max_length / qq->hold_time)) + 1;
		else
			v = qq->hold_time -
			    (qq->length * (qq->hold_time / qq->max_length)) + 1;

		if (unlikely(v < 0))
			v = 0;
	} else
		v = 0;

	return ((u64)MS_TO_NS(v));
}

static inline int
raw_event_expired(struct quark_queue *qq, struct raw_event *raw, u64 now)
{
	u64	target;

	target = raw_event_target_age(qq);
	return (raw_event_age(raw, now) >= target);
}

/*
 * Insert without a colision, cheat on the timestamp in case we do. NOTE: since
 * we bump "time" here, we shouldn't copy "time" before it sits in the tree.
 */
int
raw_event_insert(struct quark_queue *qq, struct raw_event *raw)
{
	struct raw_event	*col;
	int			 attempts = 1000;

	/*
	 * Link it first by time
	 */
	do {
		col = RB_INSERT(raw_event_by_time, &qq->raw_event_by_time, raw);
		if (likely(col == NULL))
			break;

		/*
		 * We managed to get a collision on the TSC, this happens!
		 * We just bump time by one until we can insert it.
		 */
		raw->time++;
	} while (--attempts > 0);

	if (unlikely(col != NULL)) {
		qwarnx("raw_event_by_time consecutive collisions, "
		    "this is a bug, dropping event");

		return (-1);
	}

	/*
	 * Link it in the combined tree, we accept no collisions here as the
	 * above case already saves us, but trust nothing.
	 */
	col = RB_INSERT(raw_event_by_pidtime, &qq->raw_event_by_pidtime, raw);
	if (unlikely(col != NULL)) {
		qwarnx("collision on pidtime tree, this is a bug, "
		    "dropping event");
		RB_REMOVE(raw_event_by_time, &qq->raw_event_by_time, raw);

		return (-1);
	}

	/* if (qq->min == NULL || raw_event_by_time_cmp(raw, qq->min) == -1) */
	/* 	qq->min = raw; */
	qq->length++;
	qq->stats.insertions++;

	return (0);
}

static void
raw_event_remove(struct quark_queue *qq, struct raw_event *raw)
{
	RB_REMOVE(raw_event_by_time, &qq->raw_event_by_time, raw);
	RB_REMOVE(raw_event_by_pidtime, &qq->raw_event_by_pidtime, raw);
	/* if (qq->min == raw) qq->min = NULL */
	qq->length--;
	qq->stats.removals++;
}

static int
tty_type(int major, int minor)
{
	if (major >= 136 && major <= 143)
		return (QUARK_TTY_PTS);

	if (major == 4) {
		if (minor <= 63)
			return (QUARK_TTY_CONSOLE);
		else if (minor <= 255)
			return (QUARK_TTY_TTY);
	}

	return (QUARK_TTY_UNKNOWN);
}

static void
event_storage_clear(struct quark_queue *qq)
{
	qq->event_storage.process = NULL;
	qq->event_storage.socket = NULL;
	free(qq->event_storage.packet);
	qq->event_storage.packet = NULL;
	free(qq->event_storage.file);
	qq->event_storage.file = NULL;
	bzero(&qq->event_storage.ptrace, sizeof(qq->event_storage.ptrace));
	if (qq->event_storage.module_load != NULL) {
		free(qq->event_storage.module_load->name);
		free(qq->event_storage.module_load->version);
		free(qq->event_storage.module_load->src_version);
		free(qq->event_storage.module_load);
		qq->event_storage.module_load = NULL;
	}
	if (qq->event_storage.shm != NULL) {
		free(qq->event_storage.shm->path);
		free(qq->event_storage.shm);
		qq->event_storage.shm = NULL;
	}
}

static void
gc_mark(struct quark_queue *qq, struct gc_link *gc, enum gc_type type)
{
	/* Already marked, bail */
	if (gc->gc_time)
		return;

	gc->gc_time = now64();
	gc->gc_type = type;
	TAILQ_INSERT_TAIL(&qq->event_gc, gc, gc_entry);
}

static void
gc_unlink(struct quark_queue *qq, struct gc_link *gc)
{
	if (gc->gc_time) {
		TAILQ_REMOVE(&qq->event_gc, gc, gc_entry);
		gc->gc_time = 0;
	}
}

static int
gc_collect(struct quark_queue *qq)
{
	struct gc_link	*gc;
	u64		 now;
	int		 n;

	now = now64();
	n = 0;
	while ((gc = TAILQ_FIRST(&qq->event_gc)) != NULL) {
		if (AGE(gc->gc_time, now) < qq->cache_grace_time)
			break;
		switch (gc->gc_type) {
		case GC_PROCESS:
			process_cache_delete(qq, (struct quark_process *)gc);
			break;
		case GC_SOCKET:
			socket_cache_delete(qq, (struct quark_socket *)gc);
			break;
		case GC_POD:
			pod_delete(qq, (struct quark_pod *)gc);
			break;
		default:
			qwarnx("invalid gc_type %d, will leak", gc->gc_type);
			gc_unlink(qq, gc);
		}
		n++;
	}

	qq->stats.garbage_collections += n;

	return (n);
}

static void
process_free(struct quark_process *qp)
{
	free(qp->filename);
	free(qp->cwd);
	free(qp->cmdline);
	free(qp->cgroup);
	free(qp);
}

static struct quark_process *
process_cache_get(struct quark_queue *qq, int pid, int alloc)
{
	struct quark_process	 key;
	struct quark_process	*qp;

	key.pid = pid;
	qp = RB_FIND(process_by_pid, &qq->process_by_pid, &key);
	if (qp != NULL)
		return (qp);

	if (!alloc) {
		errno = ESRCH;
		return (NULL);
	}

	qp = calloc(1, sizeof(*qp));
	if (qp == NULL)
		return (NULL);
	qp->pid = pid;
	if (RB_INSERT(process_by_pid, &qq->process_by_pid, qp) != NULL) {
		qwarnx("collision, this is a bug");
		process_free(qp);
		return (NULL);
	}

	return (qp);
}

static void
process_cache_inherit(struct quark_queue *qq, struct quark_process *qp, int ppid)
{
	struct quark_process	*parent;

	if ((parent = process_cache_get(qq, ppid, 0)) == NULL)
		return;

	/* Ignore QUARK_F_PROC? as we always have it all on fork */

	if (parent->flags & QUARK_F_COMM) {
		qp->flags |= QUARK_F_COMM;
		strlcpy(qp->comm, parent->comm, sizeof(qp->comm));
	}
	if (parent->flags & QUARK_F_FILENAME) {
		free(qp->filename);
		qp->filename = strdup(parent->filename);
		if (qp->filename != NULL)
			qp->flags |= QUARK_F_FILENAME;
	}
	/* Do we really want CMDLINE? */
	if (parent->flags & QUARK_F_CMDLINE) {
		free(qp->cmdline);
		qp->cmdline_len = 0;
		qp->cmdline = malloc(parent->cmdline_len);
		if (qp->cmdline != NULL) {
			memcpy(qp->cmdline, parent->cmdline, parent->cmdline_len);
			qp->cmdline_len = parent->cmdline_len;
			qp->flags |= QUARK_F_CMDLINE;
		}
	}
}

static void
process_cache_delete(struct quark_queue *qq, struct quark_process *qp)
{
	struct gc_link	*gc;

	gc = &qp->gc;
	RB_REMOVE(process_by_pid, &qq->process_by_pid, qp);
	if (qp->container) {
		TAILQ_REMOVE(&qp->container->processes, qp, entry_container);
		qp->container = NULL;
		qp->flags &= ~QUARK_F_CONTAINER;
	}
	gc_unlink(qq, gc);
	process_free(qp);
}

static int
process_by_pid_cmp(struct quark_process *a, struct quark_process *b)
{
	if (a->pid < b->pid)
		return (-1);
	else if (a->pid > b->pid)
		return (1);

	return (0);
}

static void
process_entity_id(struct quark_process *qp)
{
	u32		pid32_le;
	u64		ns_le;
	u8		digest[sizeof(pid32_le) + sizeof(ns_le)];

	/* No proc_time_boot, bail */
	if ((qp->flags & QUARK_F_PROC) == 0)
		return;
	/* Already computed, bail */
	if (qp->proc_entity_id[0] != 0)
		return;

	pid32_le = htole32(qp->pid);
	ns_le = htole64(qp->proc_time_boot);

	memcpy(digest, &pid32_le, sizeof(pid32_le));
	memcpy(digest + sizeof(pid32_le), &ns_le, sizeof(ns_le));
	if (qb64_ntop(digest, sizeof(digest), qp->proc_entity_id,
	    sizeof(qp->proc_entity_id)) == -1)
		qp->proc_entity_id[0] = 0;
}

/*
 * Socket stuff
 */

static struct quark_socket *
socket_cache_lookup(struct quark_queue *qq,
    struct quark_sockaddr *local, struct quark_sockaddr *remote)
{
	struct quark_socket	 key;
	struct quark_socket	*qsk;

	if ((local->af != AF_INET && local->af != AF_INET6) ||
	    (remote->af != AF_INET && remote->af != AF_INET6) ||
	    (local->af != remote->af))
		return (errno = EINVAL, NULL);

	key.local = *local;
	key.remote = *remote;
	qsk = RB_FIND(socket_by_src_dst, &qq->socket_by_src_dst, &key);
	if (qsk == NULL)
		errno = ESRCH;

	return (qsk);
}

static struct quark_socket *
socket_alloc_and_insert(struct quark_queue *qq, struct quark_sockaddr *local,
    struct quark_sockaddr *remote, enum sock_conn conn, u64 received, u64 sent,
    u32 pid_origin, u64 est_time)
{
	struct quark_socket *qsk, *col;

	qsk = calloc(1, sizeof(*qsk));
	if (qsk == NULL)
		return (NULL);
	qsk->local = *local;
	qsk->remote = *remote;
	qsk->pid_origin = qsk->pid_last_use = pid_origin;
	qsk->established_time = est_time;
	qsk->conn_origin = conn;
	qsk->bytes_received = received;
	qsk->bytes_sent = sent;

	col = RB_INSERT(socket_by_src_dst, &qq->socket_by_src_dst, qsk);
	if (col) {
		qwarnx("socket collision, this is a bug");
		free(qsk);
		qsk = NULL;
	}

	return (qsk);
}

static void
socket_cache_delete(struct quark_queue *qq, struct quark_socket *qsk)
{
	RB_REMOVE(socket_by_src_dst, &qq->socket_by_src_dst, qsk);
	gc_unlink(qq, &qsk->gc);
	free(qsk);
}

static int
socket_by_src_dst_cmp(struct quark_socket *a, struct quark_socket *b)
{
	size_t	cmplen;
	int	r;

	if (a->remote.port < b->remote.port)
		return (-1);
	else if (a->remote.port > b->remote.port)
		return (1);

	if (a->local.port < b->local.port)
		return (-1);
	else if (a->local.port > b->local.port)
		return (1);

	if (a->remote.af < b->remote.af)
		return (-1);
	else if (a->remote.af > b->remote.af)
		return (1);

	if (a->local.af < b->local.af)
		return (-1);
	else if (a->local.af > b->local.af)
		return (1);

	cmplen = a->remote.af == AF_INET ? 4 : 16;
	r = memcmp(&a->remote.addr6, &b->remote.addr6, cmplen);
	if (r != 0)
		return (r);

	cmplen = a->local.af == AF_INET ? 4 : 16;
	r = memcmp(&a->local.addr6, &b->local.addr6, cmplen);

	return (r);
}

const struct quark_socket *
quark_socket_lookup(struct quark_queue *qq,
    struct quark_sockaddr *local, struct quark_sockaddr *remote)
{
	return (socket_cache_lookup(qq, local, remote));
}

void
quark_socket_iter_init(struct quark_socket_iter *qi, struct quark_queue *qq)
{
	qi->qq = qq;
	qi->qsk = RB_MIN(socket_by_src_dst, &qq->socket_by_src_dst);
}

const struct quark_socket *
quark_socket_iter_next(struct quark_socket_iter *qi)
{
	const struct quark_socket	*qsk;

	qsk = qi->qsk;
	if (qi->qsk != NULL)
		qi->qsk = RB_NEXT(socket_by_src_dst, &qq->socket_by_src_dst, qi->qsk);

	return (qsk);
}

/*
 * Kubernetes things
 */
static struct label_node *
label_lookup(struct label_tree *labels, char *key_string)
{
	struct label_node	key, *k;

	key.key = key_string;
	k = RB_FIND(label_tree, labels, &key);
	if (k == NULL)
		errno = ESRCH;

	return (k);
}

static void
label_delete(struct label_tree *labels, struct label_node *node)
{
	RB_REMOVE(label_tree, labels, node);
	free(node->key);
	free(node->value);
	free(node);
}

static int
label_node_cmp(struct label_node *a, struct label_node *b)
{
	return (strcmp(a->key, b->key));
}

static int
container_by_id_cmp(struct quark_container *a, struct quark_container *b)
{
	return (strcmp(a->container_id, b->container_id));
}

static void
container_delete(struct quark_queue *qq, struct quark_container *container)
{
	struct quark_pod	*pod   = container->pod;
	struct quark_kube	*qkube = qq->qkube;
	struct quark_process	*qp;

	if (container->linked) {
		pod_containers_RB_REMOVE(&pod->containers, container);
		container_by_id_RB_REMOVE(&qkube->container_by_id, container);
		container->linked = 0;
	}
	while ((qp = TAILQ_FIRST(&container->processes)) != NULL) {
		TAILQ_REMOVE(&container->processes, qp, entry_container);
		qp->container = NULL;
		qp->flags &= ~QUARK_F_CONTAINER;
	}

	free(container->container_id);
	free(container->name);
	free(container->image);
	free(container->image_id);
	free(container->image_name);
	free(container->image_tag);
	free(container->image_hash);
	free(container);
}

static struct quark_container *
container_lookup(struct quark_queue *qq, char *container_id)
{
	struct quark_kube	*qkube = qq->qkube;
	struct quark_container	 key, *k;

	key.container_id = container_id;
	k = RB_FIND(container_by_id, &qkube->container_by_id, &key);
	if (k == NULL)
		errno = ESRCH;

	return (k);
}

static int
pod_by_uid_cmp(struct quark_pod *a, struct quark_pod *b)
{
	return (strcmp(a->uid, b->uid));
}

static struct quark_pod *
pod_lookup_by_uid(struct quark_queue *qq, char *uid)
{
	struct quark_kube	*qkube = qq->qkube;
	struct quark_pod	 key, *k;

	key.uid = uid;
	k = RB_FIND(pod_by_uid, &qkube->pod_by_uid, &key);
	if (k == NULL)
		errno = ESRCH;

	return (k);
}

static int
pod_insert(struct quark_queue *qq, struct quark_pod *pod)
{
	struct quark_kube	*qkube = qq->qkube;
	struct quark_pod	*col;

	if (pod->linked) {
		qwarnx("pod already linked!");
		return (-1);
	}

	col = RB_INSERT(pod_by_uid, &qkube->pod_by_uid, pod);
	if (unlikely(col != NULL))
		return (errno = EEXIST, -1);

	pod->linked = 1;

	return (0);
}

static void
pod_delete(struct quark_queue *qq, struct quark_pod *pod)
{
	struct quark_kube	*qkube = qq->qkube;
	struct quark_container	*container;
	struct label_node	*node;

	if (pod->linked) {
		RB_REMOVE(pod_by_uid, &qkube->pod_by_uid, pod);
		pod->linked = 0;
	}
	gc_unlink(qq, &pod->gc);

	while ((node = RB_ROOT(&pod->labels)) != NULL)
		label_delete(&pod->labels, node);
	/*
	 * Now we have to tear down every container from this pod.
	 * Must keep in mind that a container can already be in the gc queue, in
	 * that case we will "steal" it and delete ourselves here with
	 * everything else.
	 */
	while ((container = RB_ROOT(&pod->containers)) != NULL) {
		if (container->pod != pod) {
			qwarnx("BUG: corrupted pod<>container, leaking data");
			return;
		}
		container_delete(qq, container);
	}

	free(pod->name);
	free(pod->ns);
	free(pod->uid);
	free(pod->phase);
	free(pod);
}

static struct quark_container *
pod_lookup_container(struct quark_pod *pod, char *container_id)
{
	struct quark_container key, *k;

	key.container_id = container_id;
	k = pod_containers_RB_FIND(&pod->containers, &key);
	if (k == NULL)
		errno = ESRCH;

	return (k);
}

static void
debug_json(cJSON *json)
{
	char *debug;

	debug = cJSON_Print(json);
	fprintf(stderr, "printing cJSON\n%s\n", debug);
	free(debug);
}

static int
demux_image(struct quark_container *container)
{
	const char *tag, *tag_base, *hash;
	/*
	 * "image": "registry.k8s.io/e2e-test-images/agnhost:2.39",
	 *                                 image_name^       ^tag
	 * "imageID": "docker-pullable://registry.k8s.io/e2e-test-images/agnhost@sha256:7e8bdd271312fd25fc5ff5a8f04727be84044eb3d7d8d03611972a6752e2e11e",
	 */
	if ((tag_base = safe_basename(container->image)) != NULL &&
	    (tag = strchr(tag_base, ':')) != NULL &&
	    tag[1] != 0) {
		container->image_name = strndup(tag_base, tag - tag_base);
		if (container->image_name == NULL)
			return (-1);
		tag++;		/* skip : */
		container->image_tag = strdup(tag);
		if (container->image_tag == NULL)
			return (-1);
	}

	if ((hash = safe_basename(container->image_id)) != NULL &&
	    (hash = strchr(hash, '@')) != NULL &&
	    hash[1] != 0) {
		hash++;		/* skip @ */
		container->image_hash = strdup(hash);
		if (container->image_hash == NULL)
			return (-1);
	}

	return (0);
}

static int
kube_handle_container(struct quark_queue *qq, struct quark_pod *pod, cJSON *container_json)
{
#define GET cJSON_GetObjectItemCaseSensitive
	struct quark_kube	*qkube = qq->qkube;
	cJSON			*name, *image, *imageID, *state;
	cJSON			*waiting, *running, *terminated;
	cJSON			*containerID;
	struct quark_container	*container, *col;

	name	    = GET(container_json, "name");
	image	    = GET(container_json, "image");
	imageID     = GET(container_json, "imageID");
	state	    = GET(container_json, "state");
	waiting	    = GET(state, "waiting");
	running	    = GET(state, "running");
	terminated  = GET(state, "terminated");
	containerID = GET(container_json, "containerID");

	/*
	 * When we're waiting there's no containerID yet, so suppress it
	 */
	if (waiting != NULL && containerID == NULL)
		return (0);
	if (!cJSON_IsString(name)) {
		qwarnx("bad container name, ignoring");
		return (-1);
	}
	if (!cJSON_IsString(image)) {
		qwarnx("bad image name, ignoring");
		return (-1);
	}
	if (!cJSON_IsString(imageID)) {
		qwarnx("bad imageID, ignoring");
		return (-1);
	}
	if (!cJSON_IsObject(state)) {
		qwarnx("bad container state, ignoring");
		return (-1);
	}
	if (!cJSON_IsString(containerID)) {
		qwarnx("bad containerID, ignoring");
		return (-1);
	}
	if (waiting == NULL && running == NULL && terminated == NULL) {
		qwarnx("unknown container state, ignoring");
		return (-1);
	}
	container = pod_lookup_container(pod, containerID->valuestring);
	if (container == NULL) {
		container = calloc(1, sizeof(*container));
		if (container == NULL)
			return (-1);
		TAILQ_INIT(&container->processes);
		container->container_id = strdup(containerID->valuestring);
		if (container->container_id == NULL) {
			container_delete(qq, container);
			return (-1);
		}
		container->name = strdup(name->valuestring);
		if (container->name == NULL) {
			container_delete(qq, container);
			return (-1);
		}
		container->image = strdup(image->valuestring);
		if (container->image == NULL) {
			container_delete(qq, container);
			return (-1);
		}
		container->image_id = strdup(imageID->valuestring);
		if (container->image_id == NULL) {
			container_delete(qq, container);
			return (-1);
		}
		if (demux_image(container) == -1) {
			container_delete(qq, container);
			return (-1);
		}
		/* XXX fill moar stuff */

		/*
		 * Finally try to link it
		 */
		container->pod = pod;
		col = pod_containers_RB_INSERT(&pod->containers,
		    container);
		if (col != NULL) {
			qwarnx("unexpected container collision 1");
			container_delete(qq, container);
			return (-1);
		}
		col = container_by_id_RB_INSERT(&qkube->container_by_id,
		    container);
		/*
		 * If we get a collision on the second insert, we must manually
		 * unlink the first one, as container->linked means "both" are
		 * linked.
		 */
		if (col != NULL) {
			qwarnx("unexpected container collision 2");
			pod_containers_RB_REMOVE(&pod->containers,
			    container);
			container_delete(qq, container);
			return (-1);
		}
		container->linked = 1;
	}

	return (0);
#undef GET
}

static int
kube_handle_pod(struct quark_queue *qq, cJSON *json)
{
#define GET cJSON_GetObjectItemCaseSensitive
	struct quark_pod	*pod;
	cJSON			*metadata, *name, *namespace, *uid, *labels;
	cJSON			*spec, *containers, *status, *phase;
	cJSON			*deletionTimestamp, *containerStatuses, *label;
	cJSON			*container_json, *podIPs, *ipobj, *ip;
	char			*tmp;
	int			 new_pod, ip_found;
	struct label_node	*node, *node_aux;

	metadata	  = GET(json, "metadata");
	name		  = GET(metadata, "name");
	namespace	  = GET(metadata, "namespace");
	uid		  = GET(metadata, "uid");
	deletionTimestamp = GET(metadata, "deletionTimestamp");
	labels		  = GET(metadata, "labels");
	spec		  = GET(json, "spec");
	containers	  = GET(spec, "containers");
	status		  = GET(json, "status");
	phase		  = GET(status, "phase");
	containerStatuses = GET(status, "containerStatuses");
	podIPs		  = GET(status, "podIPs");

	if (!cJSON_IsObject(metadata)) {
		qwarnx("bad metadata");
		return (-1);
	}
	if (!cJSON_IsString(name)) {
		qwarnx("bad name");
		return (-1);
	}
	if (!cJSON_IsString(namespace)) {
		qwarnx("bad namespace");
		return (-1);
	}
	if (!cJSON_IsString(uid)) {
		qwarnx("bad uid");
		return (-1);
	}
	if (!cJSON_IsObject(spec)) {
		qwarnx("bad spec");
		return (-1);
	}
	if (!cJSON_IsArray(containers)) {
		qwarnx("bad containers");
		return (-1);
	}
	if (!cJSON_IsObject(status)) {
		qwarnx("bad status");
		return (-1);
	}
	if (!cJSON_IsString(phase)) {
		qwarnx("bad phase");
		return (-1);
	}

	pod = pod_lookup_by_uid(qq, uid->valuestring);

	/*
	 * Check for a deletion, these may happen without a filled
	 * containerStatuses.
	 */
	if (deletionTimestamp != NULL) {
		if (!cJSON_IsString(deletionTimestamp)) {
			qwarnx("bad deletionTimestamp");
			return (-1);
		}
		/* Still hasn't Succeeded, bail */
		if (strcmp(phase->valuestring, "Succeeded"))
			return (0);
		/*
		 * gc_mark is idempotent
		 */
		if (pod != NULL)
			gc_mark(qq, &pod->gc, GC_POD);

		return (0);
	}

	/*
	 * Updates and creation need containerStatuses, that's where
	 * containerID is.
	 */
	if (containerStatuses == NULL)
		return (0);
	if (!cJSON_IsArray(containerStatuses)) {
		qwarnx("bad containerStatuses");
		return (-1);
	}

	new_pod = 0;
	if (pod == NULL) {
		new_pod = 1;
		if (0)
			debug_json(json);
		pod = calloc(1, sizeof(*pod));
		if (pod == NULL)
			return (-1);
		/*
		 * Only fill immutable data, the rest is filled and/or
		 * replaced below, so we have the same code for new pods and
		 * updates.
		 */
		RB_INIT(&pod->containers);
		RB_INIT(&pod->labels);
		pod->name = strdup(name->valuestring);
		pod->ns = strdup(namespace->valuestring);
		pod->uid = strdup(uid->valuestring);
		if (pod->name == NULL ||
		    pod->ns == NULL ||
		    pod->uid == NULL) {
			pod_delete(qq, pod);
			return (-1);
		}
	}

	/* Mutable data */
	if ((tmp = strdup(phase->valuestring)) != NULL) {
		free(pod->phase);
		pod->phase = tmp;
	}

	/*
	 * Build addresses, the specification says there is at most only one ip
	 * for each address family, so consider only the first two we find.
	 */
	ip_found = 0;
	cJSON_ArrayForEach(ipobj, podIPs) {
		struct quark_sockaddr qsk;

		if (ip_found == 2)
			break;
		ip = GET(ipobj, "ip");
		if (!cJSON_IsString(ip))
			continue;
		bzero(&qsk, sizeof(qsk));
		if (inet_pton(AF_INET, ip->valuestring, &qsk.addr4) == 1) {
			qsk.af = AF_INET;
			pod->addr4 = qsk;
			strlcpy(pod->addr4_a, ip->valuestring, sizeof(pod->addr4_a));
			ip_found++;
			continue;
		}
		bzero(&qsk, sizeof(qsk));
		if (inet_pton(AF_INET6, ip->valuestring, qsk.addr6) == 1) {
			qsk.af = AF_INET6;
			pod->addr6 = qsk;
			strlcpy(pod->addr6_a, ip->valuestring, sizeof(pod->addr6_a));
			ip_found++;
			continue;
		}
	}

	/*
	 * Build labels, old labels start as unseen, and, as we loop mark the
	 * seen ones, possibly update its value and add new ones, in the end,
	 * loop again, prune all unseen ones and unmark seen.
	 */
	cJSON_ArrayForEach(label, labels) {
		char	*k, *v;

		if (!cJSON_IsString(label)) {
			qwarnx("bad label");
			continue;
		}
		k = label->string;
		v = label->valuestring;

		node = label_lookup(&pod->labels, k);
		if (node != NULL) {
			node->seen = 1;
			if (!strcmp(node->value, v))
				continue;
			if ((tmp = strdup(v)) == NULL)
				continue;
			free(node->value);
			node->value = tmp;
		} else {
			if ((node = calloc(1, sizeof(*node))) == NULL)
				continue;
			node->seen = 1;
			if ((node->key = strdup(k)) == NULL) {
				free(node);
				continue;
			}
			if ((node->value = strdup(v)) == NULL) {
				free(node->key);
				free(node);
				continue;
			}
			/* Impossible, we just looked up */
			if (RB_INSERT(label_tree, &pod->labels, node) != NULL) {
				free(node->key);
				free(node->value);
				free(node);
				continue;
			}
		}
	}
	RB_FOREACH_SAFE(node, label_tree, &pod->labels, node_aux) {
		if (node->seen) {
			node->seen = 0;
			continue;
		}
		label_delete(&pod->labels, node);
	}

	/*
	 * Build containers
	 */
	cJSON_ArrayForEach(container_json, containerStatuses) {
		if (kube_handle_container(qq, pod, container_json) == -1)
			qwarnx("kube_handle_containers failed");
	}

	/*
	 * Link pod
	 */
	if (new_pod && pod_insert(qq, pod) == -1) {
		qwarn("can't insert pod %s", pod->uid);
		pod_delete(qq, pod);
		return (-1);
	}

	return (0);
#undef GET
}

/*
 * gce://elastic-security-dev/us-east1-b/gke-demo-quark-cluster-default-pool-725cecaa-05m5"
 *  ^provider   ^project
 */
static void
parse_provider_id(struct quark_kube_node *node, const char *provider_id)
{
	char	*sep, *project_end;

	if ((sep = strstr(provider_id, "://")) == NULL)
		return;
	node->provider = strndup(provider_id, sep - provider_id);
	if (node->provider && !strcmp(node->provider, "gce"))
		node->provider[2] = 'p';
	sep += 3;
	if ((project_end = strchr(sep, '/')) == NULL)
		return;
	node->project = strndup(sep, project_end - sep);
}

static int
kube_handle_node(struct quark_queue *qq, cJSON *json)
{
#define GET cJSON_GetObjectItemCaseSensitive
	struct quark_kube_node	*node = &qq->qkube->node;
	cJSON			*metadata, *name, *uid;
	cJSON			*labels, *zone, *region;	/* optionals */
	cJSON			*spec, *providerID;		/* optionals */

	metadata = GET(json, "metadata");
	name	 = GET(metadata, "name");
	uid	 = GET(metadata, "uid");
	labels	 = GET(metadata, "labels");
	spec	 = GET(json, "spec");

	if (!cJSON_IsObject(metadata)) {
		qwarnx("bad metadata");
		return (-1);
	}
	if (!cJSON_IsString(name)) {
		qwarnx("bad name");
		return (-1);
	}
	if (!cJSON_IsString(uid)) {
		qwarnx("bad uid");
		return (-1);
	}

	/*
	 * Ignore updates
	 */
	if (node->name != NULL)
		return (0);

	/*
	 * First message
	 */
	node->name = strdup(name->valuestring);
	node->uid = strdup(uid->valuestring);
	if (node->name == NULL || node->uid == NULL) {
		free(node->name);
		free(node->uid);
		node->name = NULL;
		node->uid = NULL;
		return (-1);
	}

	/*
	 * Optional values
	 */
	zone = GET(labels, "topology.kubernetes.io/zone");
	/* try old zone key */
	if (!cJSON_IsString(zone))
		zone = GET(labels, "failure-domain.beta.kubernetes.io/zone");
	region = GET(labels, "topology.kubernetes.io/region");
	/* try old region key */
	if (!cJSON_IsString(region))
		region = GET(labels, "failure-domain.beta.kubernetes.io/region");
	/* finally commit */
	if (cJSON_IsString(zone))
		node->zone = strdup(zone->valuestring);
	if (cJSON_IsString(region))
		node->region = strdup(region->valuestring);
	/* Fetch provider and project from providerID */
	providerID = GET(spec, "providerID");
	if (cJSON_IsString(providerID))
		parse_provider_id(node, providerID->valuestring);

	return (0);
#undef GET
}

/*
 * There is only a single gcpmeta event
 */
static int
kube_handle_gcpmeta(struct quark_queue *qq, cJSON *json)
{
#define GET cJSON_GetObjectItemCaseSensitive
	struct quark_kube_node	*node = &qq->qkube->node;
	cJSON			*instance, *attributes;
	cJSON			*cluster_name, *cluster_uid;
	cJSON			*project, *numericProjectId;

	instance	 = GET(json, "instance");
	attributes	 = GET(instance, "attributes");
	cluster_name	 = GET(attributes, "cluster-name");
	cluster_uid	 = GET(attributes, "cluster-uid");
	project		 = GET(json, "project");
	numericProjectId = GET(project, "numericProjectId");

	if (cJSON_IsString(cluster_name))
		node->cluster_name = strdup(cluster_name->valuestring);
	if (cJSON_IsString(cluster_uid))
		node->cluster_uid = strdup(cluster_uid->valuestring);
	if (cJSON_IsNumber(numericProjectId)) {
		char buf[32];

		snprintf(buf, sizeof(buf), "%lld",
		    (s64)numericProjectId->valuedouble);
		node->project_id = strdup(buf);
	}

	return (0);
#undef GET
}

static int
kube_handle_cluster_version(struct quark_queue *qq, cJSON *json)
{
#define GET cJSON_GetObjectItemCaseSensitive
	struct quark_kube_node	*node = &qq->qkube->node;
	cJSON			*version;

	version	= GET(json, "version");

	if (cJSON_IsString(version))
		node->cluster_version = strdup(version->valuestring);

	return (0);
#undef GET
}

static void
kube_stop(struct quark_queue *qq)
{
	struct quark_kube	*qkube = qq->qkube;

	if (qkube == NULL || qkube->fd == -1)
		return;

	if (epoll_ctl(qq->epollfd, EPOLL_CTL_DEL, qkube->fd, NULL) == -1)
		qwarn("can't unregister qkube->fd");

	/* We don't close, the user does */
	qkube->fd = -1;
}

/*
 * Returns 0 if there's nothing else to parse, 1 otherwise
 */
static int
kube_parse_events(struct quark_queue *qq)
{
#define GET cJSON_GetObjectItemCaseSensitive
	struct quark_kube	*qkube = qq->qkube;
	size_t			 left_toread;
	char			*ev;
	u32			 ev_len;
	cJSON			*json, *kind;

	left_toread = qkube->buf_w - qkube->buf_r;
	/* In the middle of the 4byte len */
	if (left_toread < sizeof(ev_len))
		return (0);
	memcpy(&ev_len, qkube->buf + qkube->buf_r, sizeof(ev_len));
	if (ev_len > (qkube->buf_len - sizeof(ev_len))) {
		qwarnx("BUG: kube msg too long, got %d, maximum is %ld, "
		    "kubernetes events will stop",
		    ev_len, qkube->buf_len - sizeof(ev_len));

		kube_stop(qq);
		return (0);
	}
	/* Partial event */
	if (left_toread < (sizeof(ev_len) + ev_len)) {
		/*
		 * If this is a partial event and we're not in the beginning,
		 * move to the beginning
		 */
		if (qkube->buf_r != 0) {
			memmove(qkube->buf, qkube->buf + qkube->buf_r, left_toread);
			qkube->buf_r = 0;
			qkube->buf_w = left_toread;
		}

		return (0);
	}
	/* Consume event */
	ev = qkube->buf + qkube->buf_r + sizeof(ev_len);
	qkube->buf_r += sizeof(ev_len) + ev_len;

	/* Caught up, rewind */
	if (qkube->buf_r == qkube->buf_w)
		qkube->buf_r = qkube->buf_w = 0;

	if ((json = cJSON_ParseWithLength(ev, ev_len)) == NULL) {
		qwarnx("can't create json of event (len=%d)", ev_len);
		return (1);
	}
	kind = GET(json, "kind");
	if (!cJSON_IsString(kind))
		qwarnx("invalid object kind");
	else if (!strcmp("Pod", kind->valuestring))
		kube_handle_pod(qq, json);
	else if (!strcmp("Node", kind->valuestring))
		kube_handle_node(qq, json);
	else if (!strcmp("GcpMeta", kind->valuestring))
		kube_handle_gcpmeta(qq, json);
	else if (!strcmp("ClusterVersion", kind->valuestring))
		kube_handle_cluster_version(qq, json);
	else
		qwarnx("unhandled object kind %s", kind->valuestring);

	cJSON_Delete(json);

	return (1);
#undef GET
}

static void
kube_read_events(struct quark_queue *qq)
{
	struct quark_kube	*qkube = qq->qkube;
	ssize_t			 n;
	size_t			 left_towrite;

	if (qkube->fd == -1)
		return;

	/*
	 * If we didn't get EPOLLIN, check if it's time to do a read anyway, we
	 * basically only call epoll_wait() in quark_queue_block(), but on a system
	 * that is uber busy and never blocks, we would never see EPOLLIN, so
	 * make sure we try reading at least every 10ms, enough for not
	 * hammering with one syscall per event.
	 */
	if (!qkube->try_read) {
		if ((now64() - qkube->last_read) >= (u64)MS_TO_NS(10))
			qkube->try_read = 1;
		else
			return;
	}

	left_towrite = qkube->buf_len - qkube->buf_w;
	if (left_towrite == 0) {
		qwarnx("BUG: no more space in buffer, kubernetes events will stop");
		kube_stop(qq);
		return;
	}
	n = qread(qkube->fd, qkube->buf + qkube->buf_w, left_towrite);
	qkube->last_read = now64();
	qkube->try_read = 0;
	if (n == -1) {
		if (errno == EAGAIN)
			return;
		qwarn("unexpected error reading kube pipe, kubernetes events will stop");
		kube_stop(qq);
		return;
	} else if (n == 0) {
		qwarnx("unexpected EOF from kubefd pipe, kubernetes events will stop");
		kube_stop(qq);
		return;
	}
	qkube->buf_w += n;

	while (kube_parse_events(qq)) {
		;		/* NADA */
	}
}

/*
 * Build the kubernetes container_id from a cgroup
 * cgroup is what we get from the kernel, like docker-<id>.scope.
 * container_id is how kubernetes sees it, like docker://<id>.
 * Returns 0 if container_id is filled, -1 otherwise.
 * Keep this function non static so we can test it.
 */
int
kube_parse_cgroup(const char *cgroup, char *container_id, size_t container_id_len)
{
	char		*dot;
	const char	*name, *id;
	const char	*lookup_prefix;
	int		 r, id_skip;

	if ((name = safe_basename(cgroup)) == NULL)
		return (-1);

	/*
	 * Atm we only accept the systemd format, foo-<id>.scope
	 * docker-<id>.scope                 -> docker://<id>
	 * crio-<id>.scope|libpod-<id>.scope -> cri-o://<id>
	 * cri-containerd-<id>.scope         -> containerd://<id>
	 * containerd-<id>.scope             -> containerd://<id>
	 */
	id_skip = 0;

	lookup_prefix = NULL;
	if (!strncmp(name, "docker-", 7)) {
		id_skip = 7;
		lookup_prefix = "docker";
	} else if (!strncmp(name, "crio-", 5)) {
		id_skip = 5;
		lookup_prefix = "cri-o";
	} else if (!strncmp(name, "libpod-", 7)) {
		id_skip = 7;
		lookup_prefix = "cri-o";
	} else if (!strncmp(name, "cri-containerd-", 15)) {
		id_skip = 15;
		lookup_prefix = "containerd";
	} else if (!strncmp(name, "containerd-", 11)) {
		id_skip = 11;
		lookup_prefix = "containerd";
	} else
		return (-1);

	/*
	 * id starts after the foo- prefix, we still need to chomp the trailing
	 * .scope
	 */
	id = name + id_skip;

	/* copy the whole thing with the lookup_prefix, and then chomp .scope */
	r = snprintf(container_id, container_id_len,
	    "%s://%s", lookup_prefix, id);
	if (r < 0 || r >= (int)container_id_len)
		return (-1);
	dot = strrchr(container_id, '.');
	if (dot == NULL)
		return (-1);
	*dot = 0;

	return (0);
}

static void
link_kube_data(struct quark_queue *qq, struct quark_process *qp)
{
	struct quark_container	*container;
	char			 cid[NAME_MAX];

	if (qp == NULL)
		return;
	if ((qp->flags & QUARK_F_CONTAINER) || qp->container != NULL)
		return;
	if (!(qp->flags & QUARK_F_CGROUP))
		return;
	if (kube_parse_cgroup(qp->cgroup, cid, sizeof(cid)) == -1)
		return;
	if ((container = container_lookup(qq, cid)) == NULL)
		return;

	qp->container = container;
	TAILQ_INSERT_TAIL(&container->processes, qp, entry_container);
	qp->flags |= QUARK_F_CONTAINER;
}

/*
 * Reads data from kubefd for 2 seconds in order to prime kubernetes metadata,
 * we then enrich them into all our running processes.
 */
static int
kube_prime(struct quark_queue *qq)
{
	struct pollfd		 pfd;
	int			 r;
	u64			 deadline;
	struct quark_kube	*qkube = qq->qkube;

	if (qkube == NULL || qkube->fd == -1)
		return (errno = EINVAL, -1);

	bzero(&pfd, sizeof(pfd));
	pfd.fd = qkube->fd;
	pfd.events = POLLIN;

	qwarnx("priming kube events...");
	deadline = now64() + (u64)MS_TO_NS(3000);
	do {
		if ((r = poll(&pfd, 1, 25)) == -1) {
			qwarn("poll");
			return (-1);
		}
		if (r == 0)
			continue;
		qkube->try_read = 1;
		kube_read_events(qq);
		/*
		 * If read_kube_events failed at any point, fd is -1, so bail.
		 */
		if (qkube->fd == -1)
			break;
	} while (now64() < deadline);

	/*
	 * We must have received at least the node information.
	 */
	if (qkube->node.name == NULL) {
		errno = EREMOTEIO;
		qwarn("no node received by quark-kube-talker");
		return (-1);
	}

	return (0);
}

static const char *
event_flag_str(u64 flag)
{
	switch (flag) {
	case QUARK_F_PROC:
		return "PROC";
	case QUARK_F_EXIT:
		return "EXIT";
	case QUARK_F_COMM:
		return "COMM";
	case QUARK_F_FILENAME:
		return "FNAME";
	case QUARK_F_CMDLINE:
		return "CMDLINE";
	case QUARK_F_CWD:
		return "CWD";
	case QUARK_F_CGROUP:
		return "CGRP";
	default:
		return "?";
	}
}

static const char *
event_type_str(u64 event)
{
	switch (event) {
	case QUARK_EV_FORK:
		return "FORK";
	case QUARK_EV_EXEC:
		return "EXEC";
	case QUARK_EV_EXIT:
		return "EXIT";
	case QUARK_EV_SETPROCTITLE:
		return "SETPROCTITLE";
	case QUARK_EV_SOCK_CONN_ESTABLISHED:
		return "SOCK_CONN_ESTABLISHED";
	case QUARK_EV_SOCK_CONN_CLOSED:
		return "SOCK_CONN_CLOSED";
	case QUARK_EV_PACKET:
		return "PACKET";
	case QUARK_EV_BYPASS:
		return "BYPASS";
	case QUARK_EV_FILE:
		return "FILE";
	case QUARK_EV_PTRACE:
		return "PTRACE";
	case QUARK_EV_MODULE_LOAD:
		return "MODULE_LOAD";
	case QUARK_EV_SHM:
		return "SHM";
	default:
		return "?";
	}
}

static int
events_type_str(u64 events, char *buf, size_t len)
{
	int	i, n;
	u64	ev;

	if (len == 0)
		return (-1);

	for (i = 0, n = 0, *buf = 0; i < 64; i++) {
		ev = (u64)1 << i;
		if ((events & ev) == 0)
			continue;
		if (n > 0)
			if (strlcat(buf, "+", len) >= len)
				return (-1);
		if (strlcat(buf, event_type_str(ev), len) >= len)
			return (-1);
		n++;
	}

	return (0);
}

static int
entry_leader_compute(struct quark_queue *qq, struct quark_process *qp)
{
	struct quark_process	*parent;
	char			*basename, *p_basename;
	int			 tty;
	int			 is_ses_leader;

	if ((qq->flags & QQ_ENTRY_LEADER) == 0)
		return (0);

	/*
	 * Init
	 */
	if (qp->pid == 1) {
		qp->proc_entry_leader_type = QUARK_ELT_INIT;
		qp->proc_entry_leader = 1;

		return (0);
	}

	is_ses_leader = qp->pid == qp->proc_sid;

	/*
	 * All kthreads are QUARK_ELT_KTHREAD;
	 */
	if (qp->pid == 2 || qp->proc_ppid == 2) {
		qp->proc_entry_leader_type = QUARK_ELT_KTHREAD;
		qp->proc_entry_leader = is_ses_leader ? qp->pid : 2;

		return (0);
	}

	tty = tty_type(qp->proc_tty_major, qp->proc_tty_minor);

	basename = NULL;
	if (qp->flags & QUARK_F_FILENAME)
		basename = strrchr(qp->filename, '/');
	if (basename == NULL)
		basename = "";
	else
		basename++;

	/*
	 * CONSOLE only considers the login process, keep the same behaviour
	 * from other elastic products.
	 */
	if (is_ses_leader) {
		if (tty == QUARK_TTY_TTY) {
			qp->proc_entry_leader_type = QUARK_ELT_TERM;
			qp->proc_entry_leader = qp->pid;

			return (0);
		}

		if (tty == QUARK_TTY_CONSOLE && !strcmp(basename, "login")) {
			qp->proc_entry_leader_type = QUARK_ELT_TERM;
			qp->proc_entry_leader = qp->pid;

			return (0);
		}
	}

	/*
	 * Fetch the parent
	 */
	parent = process_cache_get(qq, qp->proc_ppid, 0);
	if (parent == NULL || parent->proc_entry_leader_type == QUARK_ELT_UNKNOWN)
		return (-1);

	/*
	 * Since we didn't hit anything, inherit from parent. Non leaders are
	 * done.
	 */
	qp->proc_entry_leader_type = parent->proc_entry_leader_type;
	qp->proc_entry_leader = parent->proc_entry_leader;
	if (!is_ses_leader)
		return (0);

#define STARTS_WITH(_x, _y) (!strncmp(_x, _y, strlen(_y)))
	/*
	 * Filter these out, keep same behaviour of other elastic products.
	 */
	if (STARTS_WITH(basename, "runc") ||
	    STARTS_WITH(basename, "containerd-shim") ||
	    STARTS_WITH(basename, "calico-node") ||
	    STARTS_WITH(basename, "check-status") ||
	    STARTS_WITH(basename, "pause") ||
	    STARTS_WITH(basename, "conmon"))
		return (0);

	p_basename = NULL;
	if (parent->flags & QUARK_F_FILENAME)
		p_basename = strrchr(parent->filename, '/');
	if (p_basename == NULL)
		p_basename = "";
	else
		p_basename++;

	/*
	 * SSM.
	 */
	if (tty == QUARK_TTY_PTS &&
	    !strcmp(p_basename, "ssm-session-worker")) {
		qp->proc_entry_leader_type = QUARK_ELT_SSM;
		qp->proc_entry_leader = qp->pid;

		return (0);
	}

	/*
	 * SSHD. If we're a direct descendant of sshd, but we're not sshd
	 * ourselves: we're an entry group leader for sshd.
	 */
	if (!strcmp(p_basename, "sshd") && strcmp(basename, "sshd")) {
		qp->proc_entry_leader_type = QUARK_ELT_SSHD;
		qp->proc_entry_leader = qp->pid;

		return (0);
	}

	/*
	 * Container. Similar dance to sshd but more names, cloud-defend ignores
	 * basename here.
	 */
	if (STARTS_WITH(p_basename, "containerd-shim") ||
	    STARTS_WITH(p_basename, "runc") ||
	    STARTS_WITH(p_basename, "conmon")) {
		qp->proc_entry_leader_type = QUARK_ELT_CONTAINER;
		qp->proc_entry_leader = qp->pid;

		return (0);
	}
#undef STARTS_WITH

	if (qp->proc_entry_leader == QUARK_ELT_UNKNOWN)
		qwarnx("%d (%s) is UNKNOWN (tty=%d)",
		    qp->pid, qp->filename ? qp->filename : "null", tty);

	return (0);
}

struct proc_node {
	u32			pid;
	TAILQ_ENTRY(proc_node)	entry;
};

TAILQ_HEAD(proc_node_list, proc_node);

static int
entry_leader_build_walklist(struct quark_queue *qq, struct proc_node_list *list)
{
	struct proc_node	*node, *new_node;
	struct quark_process	*qp;

	TAILQ_INIT(list);

	/*
	 * Look for the root nodes, this is init(pid = 1) and kthread(pid = 2),
	 * but maybe there's something else in the future or in the past so
	 * don't hardcode.
	 */

	RB_FOREACH(qp, process_by_pid, &qq->process_by_pid) {
		if (qp->proc_ppid != 0)
			continue;

		new_node = calloc(1, sizeof(*new_node));
		if (new_node == NULL)
			goto fail;
		new_node->pid = qp->pid;
		TAILQ_INSERT_TAIL(list, new_node, entry);
	}

	/*
	 * Now do the "recursion"
	 */
	TAILQ_FOREACH(node, list, entry) {
		RB_FOREACH(qp, process_by_pid, &qq->process_by_pid) {
			if (qp->proc_ppid != node->pid)
				continue;

			new_node = calloc(1, sizeof(*new_node));
			if (new_node == NULL)
				goto fail;
			new_node->pid = qp->pid;
			TAILQ_INSERT_TAIL(list, new_node, entry);
		}
	}

	return (0);

fail:
	while ((node = TAILQ_FIRST(list)) != NULL) {
		TAILQ_REMOVE(list, node, entry);
		free(node);
	}

	return (-1);
}

static int
entry_leaders_build(struct quark_queue *qq)
{
	struct quark_process	*qp;
	struct proc_node	*node;
	struct proc_node_list	 list;

	if ((qq->flags & QQ_ENTRY_LEADER) == 0)
		return (0);

	if (entry_leader_build_walklist(qq, &list) == -1)
		return (-1);

	while ((node = TAILQ_FIRST(&list)) != NULL) {
		qp = process_cache_get(qq, node->pid, 0);
		if (qp == NULL)
			goto fail;
		if (entry_leader_compute(qq, qp) == -1)
			qwarnx("unknown entry_leader for pid %d", qp->pid);
		TAILQ_REMOVE(&list, node, entry);
		free(node);
	}

	return (0);

fail:
	while ((node = TAILQ_FIRST(&list)) != NULL) {
		TAILQ_REMOVE(&list, node, entry);
		free(node);
	}

	return (-1);
}

static const char *
entry_leader_type_str(u32 entry_leader_type)
{
	switch (entry_leader_type) {
	case QUARK_ELT_UNKNOWN:
		return "UNKNOWN";
	case QUARK_ELT_INIT:
		return "INIT";
	case QUARK_ELT_KTHREAD:
		return "KTHREAD";
	case QUARK_ELT_SSHD:
		return "SSHD";
	case QUARK_ELT_SSM:
		return "SSM";
	case QUARK_ELT_CONTAINER:
		return "CONTAINER";
	case QUARK_ELT_TERM:
		return "TERM";
	case QUARK_ELT_CONSOLE:
		return "CONSOLE";
	default:
		return "?";
	}
}

static void
file_op_mask_str(u32 op_mask, char *buf, size_t len)
{
	int		 op, first;
	const char	*s;

	*buf = 0;
	first = 1;
	while ((op = ffs(op_mask)) != 0) {
		op = (1 << (op - 1));
		switch (op) {
		case QUARK_FILE_OP_CREATE:
			s = "CREATE";
			break;
		case QUARK_FILE_OP_REMOVE:
			s = "REMOVE";
			break;
		case QUARK_FILE_OP_MOVE:
			s = "MOVE";
			break;
		case QUARK_FILE_OP_MODIFY:
			s = "MODIFY";
			break;
		default:
			s = "INVALID";
			break;
		}
		if (!first)
			(void)strlcat(buf, "|", len);
		first = 0;
		(void)strlcat(buf, s, len);
		op_mask &= ~op;
	}
}

#define P(...)						\
	do {						\
		if (fprintf(f, __VA_ARGS__) < 0)	\
			return (-1);			\
	} while(0)

#define PF(_flag, ...)						\
	do {							\
		if (fprintf(f, "  %.4s\t", _flag) < 0)		\
			return (-1);				\
		P(__VA_ARGS__);					\
	} while(0)						\

int
quark_event_dump(const struct quark_event *qev, FILE *f)
{
	const char			*fl;
	char				 buf[1024];
	const struct quark_process	*qp;
	const struct quark_socket	*qsk;
	const struct quark_packet	*packet;
	const struct quark_file		*file;
	const struct quark_pod		*pod;
	const struct quark_container	*container;
	const struct quark_ptrace	*ptrace;
	int				 pid;

	if (qev->events == QUARK_EV_BYPASS) {
		P("*");
		fflush(f);

		return (0);
	}

	qp = qev->process;
	qsk = qev->socket;
	packet = qev->packet;
	file = qev->file;

	pid = qp != NULL ? qp->pid : 0;
	events_type_str(qev->events, buf, sizeof(buf));
	P("->%d", pid);
	if (qev->events)
		P(" (%s)", buf);
	P("\n");

	if (qev->events & (QUARK_EV_SOCK_CONN_ESTABLISHED|QUARK_EV_SOCK_CONN_CLOSED)) {
		char local[INET6_ADDRSTRLEN], remote[INET6_ADDRSTRLEN];
		fl = "SOCK";

		if (qsk == NULL)
			return (-1);

		if (inet_ntop(qsk->local.af, &qsk->local.addr6,
		    local, sizeof(local)) == NULL)
			strlcpy(local, "bad address", sizeof(local));

		if (inet_ntop(qsk->remote.af, &qsk->remote.addr6,
		    remote, sizeof(remote)) == NULL)
			strlcpy(remote, "bad address", sizeof(remote));

		PF(fl, "local=%s:%d remote=%s:%d received=%llu sent=%llu\n",
		    local, ntohs(qsk->local.port),
		    remote, ntohs(qsk->remote.port),
		    qsk->bytes_received, qsk->bytes_sent);
	}

	if (qev->events & QUARK_EV_PACKET) {
		fl = "PKT";

		if (packet == NULL)
			return (-1);

		PF(fl, "origin=%s, len=%zd/%zd\n",
		    packet->origin == QUARK_PACKET_ORIGIN_DNS ? "dns" : "?",
		    packet->cap_len, packet->orig_len);
		sshbuf_dump_data(packet->data, packet->cap_len, f);
	}

	if (qev->events & QUARK_EV_FILE) {
		fl = "FILE";

		if (file == NULL)
			return (-1);

		file_op_mask_str(file->op_mask, buf, sizeof(buf));
		PF(fl, "op=%s\n", buf);
		if (file->path != NULL)
			PF(fl, "path=%s\n", file->path);
		if (file->old_path != NULL)
			PF(fl, "old_path=%s\n", file->old_path);
		if (file->sym_target != NULL)
			PF(fl, "sym_target=%s\n",
			    file->sym_target);
		PF(fl, "mode=0%o uid=%d gid=%d size=%llu inode=%llu\n",
		    file->mode, file->uid, file->gid, file->size, file->inode);
		PF(fl, "atime=%llu mtime=%llu ctime=%llu\n",
		    file->atime, file->mtime, file->ctime);
	}

	if (qev->events & QUARK_EV_PTRACE) {
		fl = "PTRACE";

		ptrace = &qev->ptrace;

		PF(fl, "pid=%d request=0x%llx addr=0x%llx data=0x%llx\n",
		    ptrace->child_pid, ptrace->request,
		    ptrace->addr, ptrace->data);
	}

	if (qp == NULL)
		return (-1);

	if (qp->flags & QUARK_F_COMM) {
		fl = event_flag_str(QUARK_F_COMM);
		PF(fl, "comm=%s\n", qp->comm);
	}

	if (qp->flags & QUARK_F_CMDLINE) {
		struct quark_cmdline_iter	 qcmdi;
		const char			*arg;
		int				 first = 1;

		fl = event_flag_str(QUARK_F_CMDLINE);

		PF(fl, "cmdline=");
		P("[ ");

		quark_cmdline_iter_init(&qcmdi, qp->cmdline, qp->cmdline_len);
		while ((arg = quark_cmdline_iter_next(&qcmdi)) != NULL) {
			if (!first)
				P(", ");
			P("%s", arg);
			first = 0;
		}

		P(" ]\n");
	}
	if (qp->flags & QUARK_F_PROC) {
		fl = event_flag_str(QUARK_F_PROC);
		PF(fl, "ppid=%d\n", qp->proc_ppid);
		PF(fl, "uid=%d gid=%d suid=%d sgid=%d "
		    "euid=%d egid=%d pgid=%d sid=%d\n",
		    qp->proc_uid, qp->proc_gid, qp->proc_suid,
		    qp->proc_sgid, qp->proc_euid, qp->proc_egid,
		    qp->proc_pgid, qp->proc_sid);
		PF(fl, "cap_inheritable=0x%llx cap_permitted=0x%llx "
		    "cap_effective=0x%llx\n",
		    qp->proc_cap_inheritable,
		    qp->proc_cap_permitted, qp->proc_cap_effective);
		PF(fl, "cap_bset=0x%llx cap_ambient=0x%llx\n",
		    qp->proc_cap_bset, qp->proc_cap_ambient);
		PF(fl, "time_boot=%llu tty_major=%d tty_minor=%d\n",
		    qp->proc_time_boot,
		    qp->proc_tty_major, qp->proc_tty_minor);
		PF(fl, "uts_inonum=%u ipc_inonum=%u\n",
		    qp->proc_uts_inonum, qp->proc_ipc_inonum);
		PF(fl, "mnt_inonum=%u net_inonum=%u\n",
		    qp->proc_mnt_inonum, qp->proc_net_inonum);
		PF(fl, "entity_id=%s, entry_leader_type=%s entry_leader=%d\n",
		    qp->proc_entity_id,
		    entry_leader_type_str(qp->proc_entry_leader_type),
		    qp->proc_entry_leader);
	}
	if (qp->flags & QUARK_F_CWD) {
		fl = event_flag_str(QUARK_F_CWD);
		PF(fl, "cwd=%s\n", qp->cwd);
	}
	if (qp->flags & QUARK_F_FILENAME) {
		fl = event_flag_str(QUARK_F_FILENAME);
		PF(fl, "filename=%s\n", qp->filename);
	}
	if (qp->flags & QUARK_F_CGROUP) {
		fl = event_flag_str(QUARK_F_CGROUP);
		PF(fl, "cgroup=%s\n", qp->cgroup);
	}
	if (qp->flags & QUARK_F_EXIT) {
		fl = event_flag_str(QUARK_F_EXIT);
		PF(fl, "exit_code=%d exit_time=%llu\n",
		    qp->exit_code, qp->exit_time_event);
	}

	if (qp->flags & QUARK_F_CONTAINER) {
		container = qp->container;
		pod = container ? container->pod : NULL;

		if (pod != NULL) {
			int			 first = 1;
			struct label_node	*node;

			fl = "POD";
			PF(fl, "name=%s namespace=%s\n",
			    pod->name, pod->ns);
			PF(fl, "uid=%s phase=%s\n",
			    pod->uid, pod->phase);
			PF(fl, "labels=");
			P("[ ");

			/* cast to deconstify */
			RB_FOREACH(node, label_tree, (struct label_tree *)&pod->labels) {
				if (!first)
					P(", ");
				P("%s=%s", node->key, node->value);
				first = 0;
			}

			P(" ]\n");
		}
		if (container != NULL) {
			fl = "CONT";
			PF(fl, "name=%s image=%s\n", container->name, container->image);
			PF(fl, "container_id=%s\n", container->container_id);
		}
	}

	fflush(f);

	return (0);
}
#undef PF
#undef P

/* User facing version of process_cache_lookup() */
const struct quark_process *
quark_process_lookup(struct quark_queue *qq, int pid)
{
	return (process_cache_get(qq, pid, 0));
}

void
quark_process_iter_init(struct quark_process_iter *qi, struct quark_queue *qq)
{
	qi->qq = qq;
	qi->qp = RB_MIN(process_by_pid, &qq->process_by_pid);
}

const struct quark_process *
quark_process_iter_next(struct quark_process_iter *qi)
{
	const struct quark_process	*qp;

	qp = qi->qp;
	if (qi->qp != NULL)
		qi->qp = RB_NEXT(process_by_pid, &qq->process_by_pid, qi->qp);

	return (qp);
}

void
quark_cmdline_iter_init(struct quark_cmdline_iter *qcmdi,
    const char *cmdline, size_t cmdline_len)
{
	qcmdi->cmdline = cmdline;
	qcmdi->cmdline_len = cmdline_len;
	qcmdi->off = 0;
}

const char *
quark_cmdline_iter_next(struct quark_cmdline_iter *qcmdi)
{
	char *p;
	const char *arg;

	if (qcmdi->off >= qcmdi->cmdline_len)
		return (NULL);

	p = memchr(qcmdi->cmdline + qcmdi->off, 0,
	    qcmdi->cmdline_len - qcmdi->off);
	/* Technically impossible, but be paranoid */
	if (p == NULL)
		return (NULL);
	arg = qcmdi->cmdline + qcmdi->off;

	/* Point past NUL */
	qcmdi->off = p - qcmdi->cmdline + 1;

	return (arg);
}

static struct quark_event *
raw_event_process(struct quark_queue *qq, struct raw_event *src)
{
	struct quark_process		*qp;
	struct quark_event		*dst;
	struct raw_event		*agg;
	struct raw_task			*raw_fork, *raw_exit, *raw_task;
	struct raw_comm			*raw_comm;
	struct raw_exec			*raw_exec;
	struct raw_exec_connector	*raw_exec_connector;
	char				*comm;
	char				*cwd;
	char				*args;
	size_t				 args_len;
	u64				 events;

	dst = &qq->event_storage;
	raw_fork = NULL;
	raw_exit = NULL;
	raw_task = NULL;
	raw_comm = NULL;
	raw_exec = NULL;
	raw_exec_connector = NULL;
	comm = NULL;
	cwd = NULL;
	args = NULL;
	args_len = 0;

	/* XXX pass if this is a fork down, so we can evict the old one XXX */
	qp = process_cache_get(qq, src->pid, 1);
	if (qp == NULL)
		return (NULL);

	events = 0;

	switch (src->type) {
	case RAW_WAKE_UP_NEW_TASK:
		events |= QUARK_EV_FORK;
		raw_fork = &src->task;
		break;
	case RAW_EXEC:
		events |= QUARK_EV_EXEC;
		raw_exec = &src->exec;
		break;
	case RAW_EXIT_THREAD:
		events |= QUARK_EV_EXIT;
		raw_exit = &src->task;
		break;
	case RAW_COMM:
		events |= QUARK_EV_SETPROCTITLE;
		raw_comm = &src->comm;
		break;
	case RAW_EXEC_CONNECTOR:
		events |= QUARK_EV_EXEC;
		raw_exec_connector = &src->exec_connector;
		break;
	default:
		return (NULL);
		break;		/* NOTREACHED */
	};

	TAILQ_FOREACH(agg, &src->agg_queue, agg_entry) {
		switch (agg->type) {
		case RAW_WAKE_UP_NEW_TASK:
			raw_fork = &agg->task;
			events |= QUARK_EV_FORK;
			break;
		case RAW_EXEC:
			events |= QUARK_EV_EXEC;
			raw_exec = &agg->exec;
			break;
		case RAW_EXIT_THREAD:
			events |= QUARK_EV_EXIT;
			raw_exit = &agg->task;
			break;
		case RAW_COMM:
			events |= QUARK_EV_SETPROCTITLE;
			raw_comm = &agg->comm;
			break;
		case RAW_EXEC_CONNECTOR:
			events |= QUARK_EV_EXEC;
			raw_exec_connector = &agg->exec_connector;
			break;
		default:
			break;
		}
	}

	/* QUARK_F_PROC */
	if (raw_fork != NULL) {
		process_cache_inherit(qq, qp, raw_fork->ppid);
		raw_task = raw_fork;
		free(cwd);
		cwd = raw_task->cwd;
		raw_task->cwd = NULL;
	}
	if (raw_exit != NULL) {
		qp->flags |= QUARK_F_EXIT;

		qp->exit_code = raw_exit->exit_code;
		if (raw_exit->exit_time_event)
			qp->exit_time_event = quark.boottime + raw_exit->exit_time_event;
		raw_task = raw_exit;
		/* cwd is invalid, don't collect */
		/* NOTE: maybe there are more things we _don't_ want from exit */
	}
	if (raw_exec != NULL) {
		qp->flags |= QUARK_F_FILENAME;

		free(qp->filename);
		qp->filename = raw_exec->filename;
		raw_exec->filename = NULL;
		if (raw_exec->flags & RAW_EXEC_F_EXT) {
			free(args);
			args = raw_exec->ext.args;
			raw_exec->ext.args = NULL;
			args_len = raw_exec->ext.args_len;
			raw_task = &raw_exec->ext.task;
			free(cwd);
			cwd = raw_task->cwd;
			raw_task->cwd = NULL;
		}
	}
	if (raw_exec_connector != NULL) {
		free(args);
		args = raw_exec_connector->args;
		raw_exec_connector->args = NULL;
		args_len = raw_exec_connector->args_len;
		raw_task = &raw_exec_connector->task;
		free(cwd);
		cwd = raw_task->cwd;
		raw_task->cwd = NULL;
	}
	if (raw_task != NULL) {
		qp->flags |= QUARK_F_PROC;

		qp->proc_cap_inheritable = raw_task->cap_inheritable;
		qp->proc_cap_permitted = raw_task->cap_permitted;
		qp->proc_cap_effective = raw_task->cap_effective;
		qp->proc_cap_bset = raw_task->cap_bset;
		qp->proc_cap_ambient = raw_task->cap_ambient;
		/*
		 * Never change proc_time_boot after set, if we get
		 * proc_time_boot from /proc it has less precision, so the
		 * values would differ after an exec/exit. It makes more sense
		 * for this to be immutable than to "upgrade" to the higher
		 * precision one.
		 */
		if (qp->proc_time_boot == 0)
			qp->proc_time_boot = quark.boottime +
			    raw_task->start_boottime;
		qp->proc_ppid = raw_task->ppid;
		qp->proc_uid = raw_task->uid;
		qp->proc_gid = raw_task->gid;
		qp->proc_suid = raw_task->suid;
		qp->proc_sgid = raw_task->sgid;
		qp->proc_euid = raw_task->euid;
		qp->proc_egid = raw_task->egid;
		qp->proc_pgid = raw_task->pgid;
		qp->proc_sid = raw_task->sid;
		qp->proc_tty_major = raw_task->tty_major;
		qp->proc_tty_minor = raw_task->tty_minor;
		qp->proc_uts_inonum = raw_task->uts_inonum;
		qp->proc_ipc_inonum = raw_task->ipc_inonum;
		qp->proc_mnt_inonum = raw_task->mnt_inonum;
		qp->proc_net_inonum = raw_task->net_inonum;

		/* Don't set cwd as it's not valid on exit */
		comm = raw_task->comm;

		if (raw_task->cgroup != NULL) {
			qp->flags |= QUARK_F_CGROUP;
			free(qp->cgroup);
			qp->cgroup = raw_task->cgroup;
			raw_task->cgroup = NULL;
		}

		/* Depends on QUARK_F_PROC, idempotent */
		process_entity_id(qp);
	}
	if (raw_comm != NULL)
		comm = raw_comm->comm; /* raw_comm always overrides */
	/*
	 * Field pointer checking, stuff the block above sets so we save some
	 * code.
	 */
	if (args != NULL) {
		qp->flags |= QUARK_F_CMDLINE;

		free(qp->cmdline);
		qp->cmdline = args;
		qp->cmdline_len = args_len;
		/* if args != NULL, args_len is > 0 */
		qp->cmdline[qp->cmdline_len - 1] = 0; /* paranoia */
		args = NULL;
		args_len = 0;
	}
	if (comm != NULL) {
		qp->flags |= QUARK_F_COMM;

		strlcpy(qp->comm, comm, sizeof(qp->comm));
	}
	if (cwd != NULL) {
		qp->flags |= QUARK_F_CWD;

		free(qp->cwd);
		qp->cwd = cwd;
		cwd = NULL;
	}

	if (qp->flags == 0)
		qwarnx("no flags");

	if (events & (QUARK_EV_FORK | QUARK_EV_EXEC)) {
		if (entry_leader_compute(qq, qp) == -1)
			qwarnx("unknown entry_leader for pid %d", qp->pid);
	}

	/*
	 * On the very unlikely case that pids get re-used, we might
	 * see an old qp for a new process, which could prompt us in
	 * trying to remove it twice. In other words, gc_time guards
	 * presence in the TAILQ.
	 */
	if (raw_exit != NULL)
		gc_mark(qq, &qp->gc, GC_PROCESS);
	dst->events = events;
	dst->process = qp;

	return (dst);
}

/*
 * /proc parsing
 */

struct sproc_socket {
	RB_ENTRY(sproc_socket)	entry_by_inode;
	uint64_t		inode;
	struct quark_socket	socket;
};

static int
sproc_socket_by_inode_cmp(struct sproc_socket *a, struct sproc_socket *b)
{
	if (a->inode < b->inode)
		return (-1);
	else if (a->inode > b->inode)
		return (1);

	return (0);
}

RB_HEAD(sproc_socket_by_inode, sproc_socket);

RB_PROTOTYPE(sproc_socket_by_inode, sproc_socket,
    entry_by_inode, sproc_socket_by_inode_cmp);
RB_GENERATE(sproc_socket_by_inode, sproc_socket,
    entry_by_inode, sproc_socket_by_inode_cmp);

static int
sproc_status_line(struct quark_process *qp, const char *k, const char *v)
{
	const char		*errstr;

	if (*v == 0)
		return (0);

	if (!strcmp(k, "Pid")) {
		qp->pid = strtonum(v, 0, UINT32_MAX, &errstr);
		if (errstr != NULL)
			return (-1);
	} else if (!strcmp(k, "PPid")) {
		qp->proc_ppid = strtonum(v, 0, UINT32_MAX, &errstr);
		if (errstr != NULL)
			return (-1);
	} else if (!strcmp(k, "Uid")) {
		if (sscanf(v, "%d %d %d\n",
		    &qp->proc_uid, &qp->proc_euid, &qp->proc_suid) != 3)
			return (-1);
	} else if (!strcmp(k, "Gid")) {
		if (sscanf(v, "%d %d %d\n",
		    &qp->proc_gid, &qp->proc_egid, &qp->proc_sgid) != 3)
			return (-1);
	} else if (!strcmp(k, "CapInh")) {
		if (strtou64(&qp->proc_cap_inheritable, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapPrm")) {
		if (strtou64(&qp->proc_cap_permitted, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapEff")) {
		if (strtou64(&qp->proc_cap_effective, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapBnd")) {
		if (strtou64(&qp->proc_cap_bset, v, 16) == -1)
			return (-1);
	} else if (!strcmp(k, "CapAmb")) {
		if (strtou64(&qp->proc_cap_ambient, v, 16) == -1)
			return (-1);
	}

	return (0);
}

static int
sproc_stat(struct quark_process *qp, int dfd)
{
	int			 fd, r, ret;
	char			*buf, *p;
	u32			 pgid, sid, tty;
	unsigned long long	 starttime;

	buf = NULL;
	ret = -1;

	if ((fd = openat(dfd, "stat", O_RDONLY)) == -1) {
		qwarn("open stat");
		return (-1);
	}
	buf = load_file_nostat(fd, NULL);
	if (buf == NULL)
		goto cleanup;

	/*
	 * comm might have spaces, newlines and whatnot, procfs is nice enough
	 * to put parenthesis around them.
	 */
	p = strrchr(buf, ')');
	if (p == NULL)
		goto cleanup;
	p++;			/* Skip over ") " */
	while (isspace(*p))
		p++;
	starttime = 0;
	r = sscanf(p,
	    "%*s "		/* (3) state */
	    "%*s "		/* (4) ppid */
	    "%d "		/* (5) pgrp */
	    "%d "		/* (6) session */
	    "%d "		/* (7) tty_nr */
	    "%*s "		/* (8) tpgid */
	    "%*s "		/* (9) flags */
	    "%*s "		/* (10) minflt */
	    "%*s "		/* (11) cminflt */
	    "%*s "		/* (12) majflt */
	    "%*s "		/* (13) cmajflt */
	    "%*s "		/* (14) utime */
	    "%*s "		/* (15) stime */
	    "%*s "		/* (16) cutime */
	    "%*s "		/* (17) cstime */
	    "%*s "		/* (18) priority */
	    "%*s "		/* (19) nice */
	    "%*s "		/* (20) num_threads */
	    "%*s "		/* (21) itrealvalue */
	    "%llu ",		/* (22) starttime */
				/* ... */
	    &pgid,
	    &sid,
	    &tty,
	    &starttime);

	if (r == 4) {
		qp->proc_pgid = pgid;
		qp->proc_sid = sid;
		/* See proc(5) */
		qp->proc_tty_major = (tty >> 8) & 0xff;
		qp->proc_tty_minor = ((tty >> 12) & 0xfff00) | (tty & 0xff);
		qp->proc_time_boot =
		    quark.boottime +
		    ((starttime / (u64)quark.hz) * NS_PER_S) +
		    (((starttime % (u64)quark.hz) * NS_PER_S) / (u64)quark.hz);

		ret = 0;
	}

cleanup:
	free(buf);
	close(fd);

	return (ret);
}

static int
sproc_status(struct quark_process *qp, int dfd)
{
	int			 fd, ret;
	FILE			*f;
	ssize_t			 n;
	size_t			 line_len;
	char			*line, *k, *v;

	if ((fd = openat(dfd, "status", O_RDONLY)) == -1) {
		qwarn("open status");
		return (-1);
	}
	f = fdopen(fd, "r");
	if (f == NULL) {
		close(fd);
		return (-1);
	}

	ret = 0;
	line_len = 0;
	line = NULL;
	while ((n = getline(&line, &line_len, f)) != -1) {
		/* k:\tv\n = 5 */
		if (n < 5 || line[n - 1] != '\n') {
			qwarnx("bad line");
			ret = -1;
			break;
		}
		line[n - 1] = 0;
		k = line;
		v = strstr(line, ":\t");
		if (v == NULL) {
			qwarnx("no `:\\t` found");
			ret = -1;
			break;
		}
		*v = 0;
		v += 2;
		if (sproc_status_line(qp, k, v) == -1) {
			qwarnx("can't handle %s", k);
			ret = -1;
			break;
		}
	}
	free(line);
	fclose(f);

	return (ret);

}

static int
sproc_cmdline(struct quark_process *qp, int dfd)
{
	int	 fd;

	if ((fd = openat(dfd, "cmdline", O_RDONLY)) == -1) {
		qwarn("open cmdline");
		return (-1);
	}
	qp->cmdline_len = 0;
	qp->cmdline = load_file_nostat(fd, &qp->cmdline_len);
	close(fd);
	if (qp->cmdline == NULL)
		return (-1);
	/* if cmdline != NULL, cmdline_len > 0 */
	qp->cmdline[qp->cmdline_len - 1] = 0;

	return (0);
}

static int
sproc_cgroup(struct quark_process *qp, int dfd)
{
	int	 fd;
	size_t	 len;
	char	*cgroup, *p;

	cgroup = NULL;
	if ((fd = openat(dfd, "cgroup", O_RDONLY)) == -1) {
		qwarn("open cgroup");
		return (-1);
	}
	cgroup = load_file_nostat(fd, &len);
	close(fd);
	if (cgroup == NULL)
		return (-1);
	/*
	 * Chomp newline
	 */
	/* if cgroup != NULL, len > 0 */
	cgroup[len - 1] = 0;
	/*
	 * Min string is "0::/"
	 */
	if (strlen(cgroup) < 4)
		goto bad;
	/*
	 * Only expect cgroup v2
	 */
	if ((p = strchr(cgroup, ':')) == NULL)
		goto bad;
	p++;
	if ((p = strchr(p, ':')) == NULL)
		goto bad;
	p++;
	if (*p == 0)
		goto bad;

	qp->cgroup = strdup(p);
	free(cgroup);

	return (0);

bad:
	free(cgroup);

	return (-1);
}

/*
 * Note that defunct processes can return ENOENT on the actual link
 */
static int
sproc_namespace(struct quark_process *qp, const char *path, u32 *dst, int dfd)
{
	const char	*errstr;
	char		 buf[512], *start, *end;
	ssize_t		 n;
	u32		 v;

	/* 0 is an invalid inode, so good enough for the error case */
	*dst = 0;
	n = qreadlinkat(dfd, path, buf, sizeof(buf));
	if (n == -1)
		return (-1);
	else if (n >= (ssize_t)sizeof(buf))
		return (errno = ENAMETOOLONG, -1);
	if ((start = strchr(buf, '[')) == NULL)
		return (errno = EINVAL, -1);
	if ((end = strchr(buf, ']')) == NULL)
		return (errno = EINVAL, -1);
	start++;
	*end = 0;

	v = strtonum(start, 0, UINT32_MAX, &errstr);
	if (errstr != NULL)
		return (errno = EINVAL, -1);
	*dst = v;

	return (0);
}

static int
sproc_pid_sockets(struct quark_queue *qq,
    struct sproc_socket_by_inode *by_inode, int pid, int dfd)
{
	DIR		*dir;
	struct dirent	*d;
	int		 fdfd;

	if ((fdfd = openat(dfd, "fd", O_RDONLY)) == -1) {
		qwarn("open fd");
		return (-1);
	}
	dir = fdopendir(fdfd);
	if (dir == NULL) {
		close(fdfd);
		qwarn("fdopendir fdfd");
		return (-1);
	}

	while ((d = readdir(dir)) != NULL) {
		char			 buf[256];
		ssize_t			 n;
		u_long			 inode	= 0;
		const char		*needle = "socket:[";
		struct sproc_socket	*ss, ss_key;
		struct quark_socket	*qsk;

		if (d->d_type != DT_LNK)
			continue;
		n = qreadlinkat(fdfd, d->d_name, buf, sizeof(buf));
		if (n == -1)
			qwarn("qreadlinkat %s", d->d_name);
		if (n <= 0)
			continue;
		if (strncmp(buf, needle, strlen(needle)))
			continue;
		if (sscanf(buf, "socket:[%lu]", &inode) != 1) {
			qwarnx("sscanf can't get inode");
			continue;
		}

		bzero(&ss_key, sizeof(ss_key));
		ss_key.inode = inode;
		ss = RB_FIND(sproc_socket_by_inode, by_inode, &ss_key);
		/*
		 * We're only interested in TCP sockets, we end up finding
		 * AF_UNIX and SOCK_DGRAM here as well, so it's normal to have
		 * many misses.
		 */
		if (ss == NULL)
			continue;

		/*
		 * Another process already references the same socket. Maybe it
		 * accept(2)ed and forked.
		 */
		qsk = socket_cache_lookup(qq, &ss->socket.local, &ss->socket.remote);
		if (qsk != NULL)
			continue;

		qsk = socket_alloc_and_insert(qq, &ss->socket.local,
		    &ss->socket.remote, SOCK_CONN_SCRAPE, 0, 0, pid, now64());
		if (qsk == NULL) {
			qwarn("socket_alloc");
			continue;
		}

		qdebugx("pid %d fd %s -> %s (inode=%lu, ss=%p)", pid,
		    d->d_name, buf, inode, ss);
	}

	/* closedir() closes the backing `fdfd` */
	closedir(dir);

	return (0);
}

static int
sproc_pid(struct quark_queue *qq, struct sproc_socket_by_inode *by_inode,
    int pid, int dfd)
{
	struct quark_process	*qp;
	char			 path[PATH_MAX];

	/*
	 * This allocates and inserts it into the cache in case it's not already
	 * there, if say, sproc_status() fails, process will be largely empty,
	 * still we know there was a process there somewhere.
	 */
	qp = process_cache_get(qq, pid, 1);
	if (qp == NULL)
		return (-1);

	if (sproc_status(qp, dfd) == 0 && sproc_stat(qp, dfd) == 0)
		qp->flags |= QUARK_F_PROC;
	/* Fail silently, inonum is set to zero */
	sproc_namespace(qp, "ns/uts", &qp->proc_uts_inonum, dfd);
	sproc_namespace(qp, "ns/ipc", &qp->proc_ipc_inonum, dfd);
	sproc_namespace(qp, "ns/mnt", &qp->proc_mnt_inonum, dfd);
	sproc_namespace(qp, "ns/net", &qp->proc_net_inonum, dfd);
	process_entity_id(qp);

	/* QUARK_F_COMM */
	if (readlineat(dfd, "comm", qp->comm, sizeof(qp->comm)) > 0)
		qp->flags |= QUARK_F_COMM;
	/* QUARK_F_FILENAME */
	if (qreadlinkat(dfd, "exe", path, sizeof(path)) > 0) {
		if ((qp->filename = strdup(path)) != NULL)
			qp->flags |= QUARK_F_FILENAME;
	}
	/* QUARK_F_CMDLINE */
	if (sproc_cmdline(qp, dfd) == 0)
		qp->flags |= QUARK_F_CMDLINE;
	/* QUARK_F_CWD */
	if (qreadlinkat(dfd, "cwd", path, sizeof(path)) > 0) {
		if ((qp->cwd = strdup(path)) != NULL)
			qp->flags |= QUARK_F_CWD;
	}
	/* QUARK_F_CGROUP */
	if (sproc_cgroup(qp, dfd) == 0)
		qp->flags |= QUARK_F_CGROUP;
	/* if by_inode != NULL we are doing network, QQ_SOCK_CONN is set */
	if (by_inode != NULL)
		return (sproc_pid_sockets(qq, by_inode, pid, dfd));

	return (0);
}

static int
sproc_net_tcp_line(struct quark_queue *qq, const char *line, int af,
    struct sproc_socket_by_inode *by_inode)
{
	u_int	local_addr4, remote_addr4;
	u_int	local_addr6[4], remote_addr6[4];
	u_int	local_port, remote_port;
	u_long	inode;
	u_int	state;
	int	r;

	if (af != AF_INET && af != AF_INET6)
		return (-1);

	if (af == AF_INET) {
		r = sscanf(line,
		    "%*s "	/* sl */
		    "%x:%x "	/* local_address */
		    "%x:%x "	/* remote_address */
		    "%x "	/* st */
		    "%*s "	/* tx_queue+rx_queue */
		    "%*s "	/* tr+tm->when */
		    "%*s "	/* retnsmt */
		    "%*s "	/* uid */
		    "%*s "	/* timeout */
		    "%lu "	/* inode */
		    "%*s ",	/* ignored */
		    &local_addr4, &local_port,
		    &remote_addr4, &remote_port,
		    &state,
		    &inode);

		if (r != 6) {
			qwarnx("unexpected sscanf %d", r);
			return (-1);
		}
	}

	if (af == AF_INET6) {
		r = sscanf(line,
		    "%*s "			/* sl */
		    "%08x%08x%08x%08x:%x"	/* local_address */
		    "%08x%08x%08x%08x:%x"	/* remote_address */
		    "%x "			/* st */
		    "%*s "			/* tx_queue+rx_queue */
		    "%*s "			/* tr+tm->when */
		    "%*s "			/* retnsmt */
		    "%*s "			/* uid */
		    "%*s "			/* timeout */
		    "%lu "			/* inode */
		    "%*s ",			/* ignored */
		    &local_addr6[0], &local_addr6[1],
		    &local_addr6[2], &local_addr6[3], &local_port,
		    &remote_addr6[0], &remote_addr6[1],
		    &remote_addr6[2], &remote_addr6[3], &remote_port,
		    &state,
		    &inode);

		if (r != 12) {
			qwarnx("unexpected sscanf %d", r);
			return (-1);
		}
	}

	/*
	 * We're tracking the active side, the stack goes to ESTABLISHED when it
	 * receives the SYN/ACK. We go to TCP_CLOSE_WAIT when we get the FIN but
	 * didn't close().
	 */
	if (state != TCP_ESTABLISHED && state != TCP_CLOSE_WAIT)
		return (0);

	/*
	 * Inodes might be zero, in this case this is deemed an unnamed socket,
	 * in kernel, a named socket is one where sock->socket != NULL. An
	 * unnamed socket doesn't have a process attached to it anymore/yet.
	 */
	if (inode > 0) {
		struct sproc_socket	*ss, *col;

		if ((ss = calloc(1, sizeof(*ss))) == NULL)
			return (-1);
		ss->inode = (u64)inode;

		ss->socket.local.port = htons(local_port);
		ss->socket.remote.port = htons(remote_port);

		if (af == AF_INET) {
			ss->socket.local.af = AF_INET;
			ss->socket.local.addr4 = local_addr4;

			ss->socket.remote.af = AF_INET;
			ss->socket.remote.addr4 = remote_addr4;
		}

		if (af == AF_INET6) {
			ss->socket.local.af = AF_INET6;
			memcpy(ss->socket.local.addr6, local_addr6, 16);

			ss->socket.remote.af = AF_INET6;
			memcpy(ss->socket.remote.addr6, remote_addr6, 16);
		}

		col = RB_INSERT(sproc_socket_by_inode, by_inode, ss);
		if (col != NULL) {
			free(ss);
			qwarnx("socket collision");
			return (errno = EEXIST, -1);
		}
	}

	return (0);
}

static int
sproc_net_tcp(struct quark_queue *qq, int af, struct sproc_socket_by_inode *by_inode)
{
	int		 ret, fd, linenum;
	FILE		*f;
	ssize_t		 n;
	size_t		 line_len;
	char		*line;
	const char	*path;

	if (af != AF_INET && af != AF_INET6)
		return (-1);

	if (af == AF_INET)
		path = "/proc/net/tcp";
	else
		path = "/proc/net/tcp6";

	if ((fd = open(path, O_RDONLY)) == -1) {
		qwarn("open %s", path);
		return (-1);
	}
	f = fdopen(fd, "r");
	if (f == NULL) {
		close(fd);
		return (-1);
	}

	ret = 0;
	line_len = 0;
	line = NULL;
	for (linenum = 0; (n = getline(&line, &line_len, f)) != -1; linenum++) {
		if (n < 1 || line[n - 1] != '\n') {
			qwarnx("bad line");
			ret = -1;
			break;
		}
		line[n - 1] = 0;
		/* Skip header */
		if (linenum == 0)
			continue;

		ret = sproc_net_tcp_line(qq, line, af, by_inode);
		if (ret == -1)
			break;
	}
	free(line);
	fclose(f);

	return (ret);
}

static int
sproc_scrape_processes(struct quark_queue *qq, struct sproc_socket_by_inode *by_inode)
{
	FTS	*tree;
	FTSENT	*f, *p;
	int	 dfd, rootfd;
	char	*argv[] = { "/proc", NULL };

	if ((tree = fts_open(argv, FTS_NOCHDIR, NULL)) == NULL)
		return (-1);
	if ((rootfd = open(argv[0], O_PATH)) == -1) {
		fts_close(tree);
		return (-1);
	}

	while ((f = fts_read(tree)) != NULL) {
		if (f->fts_info == FTS_ERR || f->fts_info == FTS_NS)
			qwarnx("%s: %s", f->fts_name, strerror(f->fts_errno));
		if (f->fts_info != FTS_D)
			continue;
		fts_set(tree, f, FTS_SKIP);

		if ((p = fts_children(tree, 0)) == NULL) {
			qwarn("fts_children");
			continue;
		}
		for (; p != NULL; p = p->fts_link) {
			int		 pid;
			const char	*errstr;

			if (p->fts_info == FTS_ERR || p->fts_info == FTS_NS) {
				qwarnx("%s: %s",
				    p->fts_name, strerror(p->fts_errno));
				continue;
			}
			if (p->fts_info != FTS_D || !isnumber(p->fts_name))
				continue;

			if ((dfd = openat(rootfd, p->fts_name, O_PATH)) == -1) {
				qwarn("openat %s", p->fts_name);
				continue;
			}
			pid = strtonum(p->fts_name, 1, UINT32_MAX, &errstr);
			if (errstr != NULL) {
				qwarnx("bad pid %s: %s", p->fts_name, errstr);
				goto next;
			}
			if (sproc_pid(qq, by_inode, pid, dfd) == -1)
				qwarnx("can't scrape %s", p->fts_name);
next:
			close(dfd);
		}
	}

	close(rootfd);
	fts_close(tree);

	return (0);
}

static int
sproc_scrape(struct quark_queue *qq)
{
	int				 r;
	struct sproc_socket_by_inode	 socket_tmp_tree, *by_inode;
	struct sproc_socket		*ss;

	RB_INIT(&socket_tmp_tree);
	by_inode = NULL;

	if (qq->flags & QQ_SOCK_CONN) {
		r = sproc_net_tcp(qq, AF_INET, &socket_tmp_tree);
		if (r == -1)
			goto done;
		if (ipv6_supported()) {
			r = sproc_net_tcp(qq, AF_INET6, &socket_tmp_tree);
			if (r == -1)
				goto done;
		}

		by_inode = &socket_tmp_tree;
	}

	r = sproc_scrape_processes(qq, by_inode);

done:
	while ((ss = RB_ROOT(&socket_tmp_tree)) != NULL) {
		RB_REMOVE(sproc_socket_by_inode, &socket_tmp_tree, ss);
		free(ss);
	}

	return (r);
}

static u64
fetch_boottime(void)
{
	char		*line;
	const char	*errstr, *needle;
	u64		 btime;

	needle = "btime ";
	line = find_line_p("/proc/stat", needle);
	if (line == NULL)
		return (0);
	btime = strtonum(line + strlen(needle), 1, LLONG_MAX, &errstr);
	free(line);
	if (errstr != NULL)
		qwarnx("can't parse btime: %s", errstr);

	return (btime * NS_PER_S);
}

static int
quark_passwd_populate(struct passwd_by_uid *by_uid)
{
	char			*buf;
	long			 buf_size;
	struct passwd		*pw;
#ifdef HAVE_GETPWENT_R
	struct passwd		 pwd_storage;
#endif
	struct quark_passwd	*qpw;

	if (getenv("VALGRIND") != NULL) {
		qwarnx("running on valgrind, skipping user database.\n"
		    "glibc will dlopen nss_switch and never release it back, "
		    "which makes valgrind think there is a leak when there isn't");
		return (0);
	}

	buf = NULL;
	buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (buf_size == -1)
		buf_size = 65536;

	if ((buf = malloc(buf_size)) == NULL)
		goto bad;

	/*
	 * XXX glibc is awesome, they invent a getpwent_r that is not
	 * re-entrant, setpwent() shares the file offset.
	 */
	setpwent();
#ifdef HAVE_GETPWENT_R
	while (getpwent_r(&pwd_storage, buf, buf_size, &pw) == 0)
#else
	while ((pw = getpwent()) != NULL)
#endif /* HAVE_GETPWENT_R */
	{
		qpw = calloc(1, sizeof(*qpw));
		if (qpw == NULL)
			goto bad;
		qpw->name = strdup(pw->pw_name);
		if (qpw->name == NULL) {
			free(qpw);
			goto bad;
		}
		qpw->uid = pw->pw_uid;
		qpw->gid = pw->pw_gid;
		if (RB_INSERT(passwd_by_uid, by_uid, qpw) != NULL) {
			qwarnx("unexpected collision in pwd uid %d", qpw->uid);
			free(qpw->name);
			free(qpw);
		}
	}
	endpwent();
#ifdef HAVE_EXPLICIT_BZERO
	explicit_bzero(buf, buf_size);
#else
	bzero(buf, buf_size);
#endif
	free(buf);

	return (0);

bad:
#ifdef HAVE_EXPLICIT_BZERO
	explicit_bzero(buf, buf_size);
#else
	bzero(buf, buf_size);
#endif
	free(buf);
	while ((qpw = RB_ROOT(by_uid)) != NULL) {
		RB_REMOVE(passwd_by_uid, by_uid, qpw);
		free(qpw->name);
		free(qpw);
	}

	return (-1);
}

static int
quark_passwd_cmp(struct quark_passwd *a, struct quark_passwd *b)
{
	if (a->uid < b->uid)
		return (-1);
	else if (a->uid > b->uid)
		return (1);

	return (0);
}

struct quark_passwd *
quark_passwd_lookup(struct quark_queue *qq, uid_t uid)
{
	struct quark_passwd	key, *qpwd;

	key.uid = uid;
	qpwd = RB_FIND(passwd_by_uid, &qq->passwd_by_uid, &key);
	if (qpwd == NULL)
		errno = ESRCH;

	return (qpwd);
}

static int
quark_group_cmp(struct quark_group *a, struct quark_group *b)
{
	if (a->gid < b->gid)
		return (-1);
	else if (a->gid > b->gid)
		return (1);

	return (0);
}

struct quark_group *
quark_group_lookup(struct quark_queue *qq, gid_t gid)
{
	struct quark_group	key, *qgrp;

	key.gid = gid;
	qgrp = RB_FIND(group_by_gid, &qq->group_by_gid, &key);
	if (qgrp == NULL)
		errno = ESRCH;

	return (qgrp);
}

static int
quark_group_populate(struct group_by_gid *by_gid)
{
	char			*buf;
	long			 buf_size;
#ifdef HAVE_GETGRENT_R
	struct group		 grp_storage;
#endif
	struct group		*grp;
	struct quark_group	*qgrp;

	if (getenv("VALGRIND") != NULL) {
		qwarnx("running on valgrind, skipping group database\n"
		    "glibc will dlopen nss_switch and never release it back\n"
		    "which makes valgrind think there is a leak when there isn't");
		return (0);
	}

	buf = NULL;
	buf_size = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (buf_size == -1)
		buf_size = 65536;

	if ((buf = malloc(buf_size)) == NULL)
		goto bad;

	setgrent();
#ifdef HAVE_GETGRENT_R
	while (getgrent_r(&grp_storage, buf, buf_size, &grp) == 0)
#else
	while ((grp = (getgrent())) != NULL)
#endif
	{
		if ((qgrp = calloc(1, sizeof(*qgrp))) == NULL)
			goto bad;
		qgrp->gid = grp->gr_gid;
		if ((qgrp->name = strdup(grp->gr_name)) == NULL) {
			free(qgrp);
			goto bad;
		}
		if (RB_INSERT(group_by_gid, by_gid, qgrp) != NULL) {
			qwarnx("unexpected collision in group gid %d",
			    qgrp->gid);
			free(qgrp->name);
			free(qgrp);
		}
	}
	endgrent();
#ifdef HAVE_EXPLICIT_BZERO
	explicit_bzero(buf, buf_size);
#else
	bzero(buf, buf_size);
#endif
	free(buf);

	return (0);

bad:
#ifdef HAVE_EXPLICIT_BZERO
	explicit_bzero(buf, buf_size);
#else
	bzero(buf, buf_size);
#endif
	free(buf);
	while ((qgrp = RB_ROOT(by_gid)) != NULL) {
		RB_REMOVE(group_by_gid, by_gid, qgrp);
		free(qgrp->name);
		free(qgrp);
	}

	return (-1);
}

static int
quark_sysinfo_os_release(struct quark_sysinfo *si)
{
	FILE	*f;
	ssize_t	 n;
	size_t	 line_len;
	char	*line, *k, *v, *aux;

	if ((f = fopen("/etc/os-release", "r")) == NULL) {
		qwarn("fopen /etc/os-release");
		return (-1);
	}

	line_len = 0;
	line = NULL;
	while ((n = getline(&line, &line_len, f)) != -1) {
		if (n == 0 || line[n - 1] != '\n') {
			qwarnx("bad line");
			continue;
		}
		line[n - 1] = 0;
		k = line;
		if (*k == 0 || *k == '#')
			continue;
		v = strchr(line, '=');
		if (v == NULL) {
			qwarnx("bad line, no separator");
			continue;
		}
		*v++ = 0;
		if (*v == 0) {
			qwarnx("bad line, no value");
			continue;
		}
		if (*v == '"') {
			v++;
			aux = strchr(v, '"');
			if (aux == NULL) {
				qwarnx("unterminated line");
				continue;
			}
			*aux = 0;
		}
		if (!strcasecmp(k, "name"))
			si->os_name = strdup(v);
		else if (!strcasecmp(k, "version"))
			si->os_version = strdup(v);
		else if (!strcasecmp(k, "release_type"))
			si->os_release_type = strdup(v);
		else if (!strcasecmp(k, "id"))
			si->os_id = strdup(v);
		else if (!strcasecmp(k, "version_id"))
			si->os_version_id = strdup(v);
		else if (!strcasecmp(k, "version_codename"))
			si->os_version_codename = strdup(v);
		else if (!strcasecmp(k, "pretty_name"))
			si->os_pretty_name = strdup(v);
	}
	free(line);
	fclose(f);

	return (0);
}

static int
quark_sysinfo_ifaddrs(struct quark_sysinfo *si)
{
	struct ifaddrs		 *ifa, *ifaddrs;
	int			  af;
	size_t			  i;
	char			  buf[INET6_ADDRSTRLEN];
	char			**tmp, *buf_copy;

	if (getifaddrs(&ifaddrs) == -1) {
		qwarn("getifaddrs");

		return (-1);
	}

	/*
	 * Look for all addresses that have an ip adress
	 */
	si->ip_addrs_len = si->mac_addrs_len = 0;
	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		af = ifa->ifa_addr->sa_family;
		if (af == AF_INET) {
			struct sockaddr_in	 *sin;

			sin = (struct sockaddr_in *)ifa->ifa_addr;
			if (inet_ntop(af, &sin->sin_addr, buf, sizeof(buf)) == NULL) {
				qwarn("inet_ntop ifname %s", ifa->ifa_name);
				continue;
			}
		}
		if (af == AF_INET6) {
			struct sockaddr_in6	 *sin6;

			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (inet_ntop(af, &sin6->sin6_addr,
			    buf, sizeof(buf)) == NULL) {
				qwarn("inet_ntop ifname %s", ifa->ifa_name);
				continue;
			}
		}
		if (af == AF_INET || af == AF_INET6) {
			/* Check if unique */
			for (i = 0; i < si->ip_addrs_len; i++) {
				if (!strcmp(buf, si->ip_addrs[i]))
					goto next;
			}
			buf_copy = strdup(buf);
			if (buf_copy == NULL) {
				qwarn("strdup");
				continue;
			}
			tmp = reallocarray(si->ip_addrs,
			    si->ip_addrs_len + 1, sizeof(char *));
			if (tmp == NULL) {
				free(buf_copy);
				qwarn("reallocarray");
				continue;
			}
			si->ip_addrs = tmp;
			si->ip_addrs[si->ip_addrs_len] = buf_copy;
			si->ip_addrs_len++;
		}
		if (af == AF_PACKET) {
			struct sockaddr_ll	*sll;
			struct ether_addr	*ether, zero_ether;
			char			 eth_buf[32];

			bzero(eth_buf, sizeof(eth_buf));
			sll = (struct sockaddr_ll *)ifa->ifa_addr;
			if (sll->sll_halen != 6)
				continue;
			ether = (struct ether_addr *)sll->sll_addr;
			bzero(&zero_ether, sizeof(zero_ether));
			if (!memcmp(&zero_ether, ether, 6))
				continue;
			if ((ether_ntoa_r(ether, eth_buf)) == NULL) {
				qwarn("ether_ntoa ifname %s", ifa->ifa_name);
				continue;
			}
			/* Check if unique */
			for (i = 0; i < si->ip_addrs_len; i++) {
				if (!strcmp(eth_buf, si->ip_addrs[i]))
					goto next;
			}
			buf_copy = strdup(eth_buf);
			if (buf_copy == NULL) {
				qwarn("strdup");
				continue;
			}
			tmp = reallocarray(si->mac_addrs,
			    si->mac_addrs_len + 1, sizeof(char *));
			if (tmp == NULL) {
				free(buf_copy);
				qwarn("reallocarray");
				continue;
			}
			si->mac_addrs = tmp;
			si->mac_addrs[si->mac_addrs_len] = buf_copy;
			si->mac_addrs_len++;
		}
next:
		; /* GCC 4.8.x will freak without a statement after a label */
	}
	freeifaddrs(ifaddrs);

	return (0);
}

static void
quark_sysinfo_delete(struct quark_sysinfo *si)
{
	size_t i;

	free(si->boot_id);
	si->boot_id = NULL;
	free(si->hostname);
	si->hostname = NULL;
	/* ip_addrs */
	for (i = 0; i < si->ip_addrs_len; i++)
		free(si->ip_addrs[i]);
	free(si->ip_addrs);
	si->ip_addrs = NULL;
	si->ip_addrs_len = 0;
	/* mac_addrs */
	for (i = 0; i < si->mac_addrs_len; i++)
		free(si->mac_addrs[i]);
	free(si->mac_addrs);
	si->mac_addrs = NULL;
	si->mac_addrs_len = 0;
	/* uts_* */
	free(si->uts_sysname);
	si->uts_sysname = NULL;
	free(si->uts_nodename);
	si->uts_nodename = NULL;
	free(si->uts_release);
	si->uts_release = NULL;
	free(si->uts_version);
	si->uts_version = NULL;
	free(si->uts_machine);
	si->uts_machine = NULL;
	/* os_* */
	free(si->os_name);
	si->os_name = NULL;
	free(si->os_version);
	si->os_version = NULL;
	free(si->os_release_type);
	si->os_release_type = NULL;
	free(si->os_id);
	si->os_id = NULL;
	free(si->os_version_id);
	si->os_version_id = NULL;
	free(si->os_version_codename);
	si->os_version_codename = NULL;
	free(si->os_pretty_name);
	si->os_pretty_name = NULL;
}

static int
quark_sysinfo_init(struct quark_sysinfo *si)
{
	struct utsname	uts;
	int		r = 0;
	size_t		len;
	char		hostname[MAXHOSTNAMELEN];

	bzero(hostname, sizeof(hostname));
	if (gethostname(hostname, sizeof(hostname)) == -1)
		r = -1;
	else {
		hostname[sizeof(hostname) - 1] = 0;
		si->hostname = strdup(hostname);
	}

	si->boot_id =
	    load_file_path_nostat("/proc/sys/kernel/random/boot_id", &len);
	if (si->boot_id == NULL || len < 2) {
		free(si->boot_id);
		si->boot_id = NULL;
		r = -1;
	} else if (si->boot_id[len - 1] == '\n') /* chomp \n */
		si->boot_id[len - 1] = 0;

	if (uname(&uts) == -1)
		r = -1;
	else {
		si->uts_sysname = strdup(uts.sysname);
		si->uts_nodename = strdup(uts.nodename);
		si->uts_release = strdup(uts.release);
		si->uts_version = strdup(uts.version);
		si->uts_machine = strdup(uts.machine);
	}

	if (quark_sysinfo_os_release(si) == -1)
		r = -1;

	if (quark_sysinfo_ifaddrs(si) == -1)
		r = -1;

	return (r);
}

/*
 * Aggregation is a relationship between a parent event and a child event. In a
 * fork+exec cenario, fork is the parent, exec is the child.
 * Aggregation can be confiured as AGG_SINGLE or AGG_MULTI.
 *
 * AGG_SINGLE aggregate a single child: fork+exec+exec would result
 * in two events: (fork+exec); (exec).
 *
 * AGG_MULTI just smashes everything together, a fork+comm+comm+comm would
 * result in one event: (fork+comm), the intermediary comm values are lost.
 */

enum agg_kind {
	AGG_NONE,		/* Can't aggregate, must be zero */
	AGG_SINGLE,		/* Can aggregate only one value */
	AGG_MULTI,		/* Can aggregate multiple values */
	AGG_CUSTOM,		/* Can aggregate depending on data */
};
		     /* parent */   /* child */
const u8 agg_matrix[RAW_NUM_TYPES][RAW_NUM_TYPES] = {
	[RAW_WAKE_UP_NEW_TASK][RAW_EXEC]		= AGG_SINGLE,
	[RAW_WAKE_UP_NEW_TASK][RAW_EXEC_CONNECTOR]	= AGG_SINGLE,
	[RAW_WAKE_UP_NEW_TASK][RAW_COMM]		= AGG_MULTI,
	[RAW_WAKE_UP_NEW_TASK][RAW_EXIT_THREAD]		= AGG_SINGLE,

	[RAW_EXEC][RAW_EXEC_CONNECTOR]			= AGG_SINGLE,
	[RAW_EXEC][RAW_COMM]				= AGG_MULTI,
	[RAW_EXEC][RAW_EXIT_THREAD]			= AGG_SINGLE,

	[RAW_COMM][RAW_COMM]				= AGG_MULTI,
	[RAW_COMM][RAW_EXIT_THREAD]			= AGG_SINGLE,

	[RAW_FILE][RAW_FILE]				= AGG_CUSTOM,
};

/* used if qq->flags & QQ_MIN_AGG */
			 /* parent */   /* child */
const u8 agg_matrix_min[RAW_NUM_TYPES][RAW_NUM_TYPES] = {
	[RAW_WAKE_UP_NEW_TASK][RAW_COMM]		= AGG_MULTI,

	[RAW_EXEC][RAW_EXEC_CONNECTOR]			= AGG_SINGLE,
	[RAW_EXEC][RAW_COMM]				= AGG_MULTI,

	[RAW_COMM][RAW_COMM]				= AGG_MULTI,
};

static int
quark_init(void)
{
	unsigned int	hz;
	u64		boottime;

	if (quark.hz && quark.boottime)
		return (0);

	if ((hz = sysconf(_SC_CLK_TCK)) == (unsigned int)-1) {
		qwarn("sysconf(_SC_CLK_TCK)");
		return (-1);
	}
	if ((boottime = fetch_boottime()) == 0) {
		qwarn("can't fetch btime");
		return (-1);
	}
	quark.hz = hz;
	quark.boottime = boottime;

	return (0);
}

#define P(_f, ...)					\
	do {						\
		if (fprintf(_f, __VA_ARGS__) < 0)	\
			return (-1);			\
	} while(0)
static int
write_raw_node_attr(FILE *f, struct raw_event *raw, char *key)
{
	const char		*color;
	char			 label[4096];

	switch (raw->type) {
	case RAW_COMM:
		color = "yellow";
		(void)snprintf(label, sizeof(label), "COMM %s",
		    raw->comm.comm);
		break;
	case RAW_EXIT_THREAD:
		color = "lightseagreen";
		(void)strlcpy(label, "EXIT", sizeof(label));
		break;
	case RAW_EXEC:
		color = "lightslateblue";
		if (snprintf(label, sizeof(label), "EXEC %s",
		    raw->exec.filename) >= (int)sizeof(label))
			qwarnx("exec filename truncated");
		break;
	case RAW_WAKE_UP_NEW_TASK: {
		color = "orange";
		if (snprintf(label, sizeof(label), "NEW_TASK %d",
		    raw->pid) >= (int)sizeof(label))
			qwarnx("snprintf label");
		break;
	}
	case RAW_EXEC_CONNECTOR:
		color = "lightskyblue";
		if (snprintf(label, sizeof(label), "EXEC_CONNECTOR")
		    >= (int)sizeof(label))
			qwarnx("exec_connector truncated");
		break;
	default:
		qwarnx("%d unhandled", raw->type);
		color = "black";
		break;
	}
	P(f, "\"%s\" [label=\"%llu\\n%s\\npid %d\", fillcolor=%s];\n",
	    key, raw->time, label, raw->pid, color);

	return (0);
}

int
quark_dump_raw_event_graph(struct quark_queue *qq, FILE *by_time, FILE *by_pidtime)
{
	struct raw_event	*raw, *left, *right;
	FILE			*f;
	char			 key[256];

	f = by_time;

	P(f, "digraph {\n");
	P(f, "node [style=filled, color=black];\n");
	RB_FOREACH(raw, raw_event_by_time, &qq->raw_event_by_time) {
		snprintf(key, sizeof(key), "%llu", raw->time);
		if (write_raw_node_attr(f, raw, key) < 0)
			return (-1);
	}
	RB_FOREACH(raw, raw_event_by_time, &qq->raw_event_by_time) {
		left = RB_LEFT(raw, entry_by_time);
		right = RB_RIGHT(raw, entry_by_time);

		if (left != NULL)
			P(f, "%llu -> %llu;\n",
			    raw->time, left->time);
		if (right != NULL)
			P(f, "%llu -> %llu;\n",
			    raw->time, right->time);
	}
	P(f, "}\n");

	fflush(f);

	f = by_pidtime;

	P(f, "digraph {\n");
	P(f, "node [style=filled, color=black];\n");
	RB_FOREACH(raw, raw_event_by_pidtime, &qq->raw_event_by_pidtime) {
		snprintf(key, sizeof(key), "%d %llu",
		    raw->pid, raw->time);
		if (write_raw_node_attr(f, raw, key) < 0)
			return (-1);
	}
	RB_FOREACH(raw, raw_event_by_pidtime, &qq->raw_event_by_pidtime) {
		left = RB_LEFT(raw, entry_by_pidtime);
		right = RB_RIGHT(raw, entry_by_pidtime);

		if (left != NULL) {
			P(f, "\"%d %llu\" -> \"%d %llu\";\n",
			    raw->pid, raw->time,
			    left->pid, left->time);
		}
		if (right != NULL)
			P(f, "\"%d %llu\" -> \"%d %llu\";\n",
			    raw->pid, raw->time,
			    right->pid, right->time);
	}
	P(f, "}\n");

	fflush(f);

	return (0);
}

int
quark_dump_process_cache_graph(struct quark_queue *qq, FILE *f)
{
	struct quark_process	*qp;
	const char		*name;
	const char		*color_table[] = {
		"aqua",
		"aquamarine3",
		"azure3",
		"coral",
		"darkgoldenrod1",
		"darkolivegreen2",
		"darkorchid1",
		"firebrick3",
		"forestgreen",
		"lemonchiffon2",
		"lightslateblue",
		"lime",
		"orange2",
		"skyblue3",
		"violet",
		"yellow"
	};

	P(f, "digraph {\n");
	P(f, "ranksep=2.0;\n");
	P(f, "nodesep=0.65;\n");
	P(f, "node [style=filled, shape=box, color=black];\n");
	RB_FOREACH(qp, process_by_pid, &qq->process_by_pid) {
		uint	color_index;

		color_index = (uint)qp->proc_ppid % (uint)nitems(color_table);
		if (color_index >= nitems(color_table)) /* paranoia */
			color_index = 0;

		if (qp->flags & QUARK_F_FILENAME)
			name = qp->filename;
		else if (qp->flags & QUARK_F_COMM)
			name = qp->comm;
		else
			name = "<unknown>";
		P(f, "\"%d\" [label=\"%d\\n%s\\n", qp->pid, qp->pid, name);
		if (qp->flags & QUARK_F_COMM)
			P(f, "comm %s\\n", qp->comm);
		if (qp->flags & QUARK_F_CWD)
			P(f, "cwd %s\\n", qp->cwd);
		if (qp->flags & QUARK_F_PROC) {
			P(f, "cap_inh 0x%llx\\n", qp->proc_cap_inheritable);
			P(f, "cap_per 0x%llx\\n", qp->proc_cap_permitted);
			P(f, "cap_eff 0x%llx\\n", qp->proc_cap_effective);
			P(f, "cap_bset 0x%llx\\n", qp->proc_cap_bset);
			P(f, "cap_amb 0x%llx\\n", qp->proc_cap_ambient);
			P(f, "time_boot %llu\\n", qp->proc_time_boot);
			P(f, "uid %d\\n", qp->proc_uid);
			P(f, "gid %d\\n", qp->proc_gid);
			P(f, "suid %d\\n", qp->proc_suid);
			P(f, "sgid %d\\n", qp->proc_sgid);
			P(f, "sid %d\\n", qp->proc_sid);
			P(f, "tty_maj %d\\n", qp->proc_tty_major);
			P(f, "tty_min %d\\n", qp->proc_tty_minor);
			P(f, "el_type %s\\n",
			    entry_leader_type_str(qp->proc_entry_leader_type));
			P(f, "el_leader %d\\n", qp->proc_entry_leader);
		}
		if (qp->flags & QUARK_F_EXIT) {
			P(f, "exit %d\\n", qp->exit_code);
			P(f, "exit_time %llu\\n", qp->exit_time_event);
		}
		P(f, "flags 0x%llx\\n", qp->flags);
		P(f, "\", fillcolor=%s];\n", color_table[color_index]);
	}
	RB_FOREACH(qp, process_by_pid, &qq->process_by_pid) {
		P(f, "%d -> %d;\n", qp->proc_ppid, qp->pid);
	}
	P(f, "}\n");
	fflush(f);

	return (0);
}
#undef P

int
quark_queue_get_epollfd(struct quark_queue *qq)
{
	return (qq->epollfd);
}

void
quark_queue_get_stats(struct quark_queue *qq, struct quark_queue_stats *qs)
{
	qq->queue_ops->update_stats(qq);
	*qs = qq->stats;
}

int
quark_queue_block(struct quark_queue *qq)
{
	struct epoll_event	 ev;
	struct quark_kube	*qkube = qq->qkube;
	int			 nfd;

	if (qq->epollfd == -1)
		return (errno = EINVAL, -1);
	if ((nfd = epoll_wait(qq->epollfd, &ev, 1, 100)) == -1)
		return (-1);
	if (qkube != NULL && nfd > 0 && qkube->fd == ev.data.fd)
		qkube->try_read = 1;

	return (0);
}

void
quark_queue_default_attr(struct quark_queue_attr *qa)
{
	bzero(qa, sizeof(*qa));

	qa->flags = QQ_ALL_BACKENDS;
	qa->max_length = 10000;
	qa->cache_grace_time = 4000;	/* four seconds */
	qa->hold_time = 1000;		/* one second */
	qa->kubefd = -1;		/* disabled */
}

int
quark_queue_open(struct quark_queue *qq, struct quark_queue_attr *qa)
{
	struct quark_queue_attr	 qa_default;
	struct timespec		 unused;
	char			*ver;

	if ((ver = getenv("QUARK_VERBOSE")) != NULL) {
		const char *errstr;

		if (*ver == 0)
			quark_verbose = 0;
		else {
			quark_verbose = strtonum(ver, 0, 1000, &errstr);
			/* Just assume max */
			if (errstr != NULL)
				quark_verbose = 1000;
		}
	}

	/* Test if clock_gettime() works */
	if (clock_gettime(CLOCK_MONOTONIC, &unused) == -1)
		return (-1);

	if (qa == NULL) {
		quark_queue_default_attr(&qa_default);
		qa = &qa_default;
	}

	/*
	 * QQ_BYPASS is EBPF only
	 */
	if (qa->flags & QQ_BYPASS) {
		if ((qa->flags &
		    (QQ_KPROBE|QQ_ENTRY_LEADER|QQ_MIN_AGG|QQ_THREAD_EVENTS)) ||
		    !(qa->flags & QQ_EBPF) ||
		    qa->kubefd != -1)
			return (errno = EINVAL, -1);

		/*
		 * No buffering, we just pop one element from the ring and
		 * return
		 */
		qa->max_length = 1;
	}
	/*
	 * QQ_TTY needs QQ_BYPASS for now
	 */
	if ((qa->flags & QQ_TTY) && !(qa->flags & QQ_BYPASS))
		return (errno = EINVAL, -1);

	if ((qa->flags & QQ_ALL_BACKENDS) == 0 ||
	    qa->max_length <= 0 ||
	    qa->cache_grace_time < 0 ||
	    qa->hold_time < 10)
		return (errno = EINVAL, -1);

	if (quark_init() == -1)
		return (-1);

	bzero(qq, sizeof(*qq));

	RB_INIT(&qq->raw_event_by_time);
	RB_INIT(&qq->raw_event_by_pidtime);
	RB_INIT(&qq->process_by_pid);
	RB_INIT(&qq->socket_by_src_dst);
	RB_INIT(&qq->passwd_by_uid);
	RB_INIT(&qq->group_by_gid);
	TAILQ_INIT(&qq->event_gc);
	qq->flags = qa->flags;
	qq->max_length = qa->max_length;
	qq->cache_grace_time = MS_TO_NS(qa->cache_grace_time);
	qq->hold_time = qa->hold_time;
	qq->length = 0;
	qq->epollfd = -1;
	if (qq->flags & QQ_MIN_AGG)
		qq->agg_matrix = agg_matrix_min;
	else
		qq->agg_matrix = agg_matrix;

	if ((qq->epollfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
		qwarn("can't create epollfd");
		goto fail;
	}

	/*
	 * If we have kubernetes, initilize its state, then block for some
	 * seconds to prime all pods and containers
	 */
	if (qa->kubefd != -1) {
		int			 fl;
		struct quark_kube	*qkube;
		struct epoll_event	 ev;

		if ((qkube = calloc(1, sizeof(*qkube))) == NULL) {
			qwarn("can't allocate qkube");
			goto fail;
		}

		/*
		 * Don't blame me, blame google:
		 * https://github.com/kubernetes/kubernetes/blob/db1990f48b92d603f469c1c89e2ad36da1b74846/test/integration/master/synthetic_master_test.go#L315
		 * We allocate 4MB to give some slack.
		 */
		qkube->buf_len = 1 << 22; /* 4MB */
		qkube->buf_r = 0;
		qkube->buf_w = 0;
		qkube->fd = qa->kubefd;
		qkube->try_read = 1;
		qkube->last_read = 0;
		RB_INIT(&qkube->pod_by_uid);
		RB_INIT(&qkube->container_by_id);

		if ((fl = fcntl(qkube->fd, F_GETFL)) == -1) {
			qwarn("can't get kubefd flags");
			free(qkube);
			goto fail;
		}
		if (fcntl(qkube->fd, F_SETFL, fl | O_NONBLOCK) == -1) {
			qwarn("can't set kubefd to nonblocking");
			free(qkube);
			goto fail;
		}
		if ((qkube->buf = calloc(1, qkube->buf_len)) == NULL) {
			qwarn("can't allocate qkube buffer");
			free(qkube);
			goto fail;
		}

		bzero(&ev, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = qkube->fd;
		if (epoll_ctl(qq->epollfd, EPOLL_CTL_ADD, qkube->fd,
		    &ev) == -1) {
			qwarn("can't add kube fd to epoll");
			free(qkube->buf);
			free(qkube);
			goto fail;
		}

		qq->qkube = qkube;

		/*
		 * Prime our cache
		 */
		if (kube_prime(qq) == -1) {
			qwarn("can't prime kubernetes metadata");
			goto fail;
		}
	}

	/*
	 * Open the rings
	 */
	if (bpf_queue_open(qq) && kprobe_queue_open(qq)) {
		qwarnx("all backends failed");
		goto fail;
	}

	if ((qq->flags & QQ_BYPASS) == 0) {
		/*
		 * Now that the rings are opened, we can scrape proc. If we would scrape
		 * before opening them, there would be a small window where we could
		 * lose new processes.
		 */
		if (sproc_scrape(qq) == -1) {
			qwarnx("can't scrape /proc");
			goto fail;
		}

		/*
		 * Compute all entry leaders
		 */
		if (entry_leaders_build(qq) == -1) {
			qwarnx("can't compute entry leaders");
			goto fail;
		}
	}

	/*
	 * At this point, existing processes have been loaded and kubernetes
	 * metada has been primed. Now it's the time to correlate both.
	 */
	if (qq->qkube != NULL) {
		struct quark_process	*qp;

		RB_FOREACH(qp, process_by_pid, &qq->process_by_pid) {
			link_kube_data(qq, qp);
		}
	}

	/*
	 * Build username database, really only used for ECS and event dumping.
	 */
	if (quark_passwd_populate(&qq->passwd_by_uid) == -1)
		qwarn("Can't build user database, not fatal");

	/*
	 * Build group database, really only used for ECS and event dumping.
	 */
	if (quark_group_populate(&qq->group_by_gid) == -1)
		qwarn("Can't build group database, not fatal");

	/*
	 * Build quark_sysinfo, really only used for ECS for now, not fatal
	 */
	if (quark_sysinfo_init(&qq->sysinfo) == -1)
		qwarn("Can't init quark_sysinfo, not fatal");

	return (0);

fail:
	quark_queue_close(qq);

	return (-1);
}

/*
 * Must be careful enough that can be called if quark_queue_open() fails
 */
void
quark_queue_close(struct quark_queue *qq)
{
	struct raw_event	*raw;
	struct quark_process	*qp;
	struct quark_socket	*qsk;
	struct quark_pod	*pod;
	struct quark_passwd	*qpw;
	struct quark_group	*qgrp;

	/* Don't forget the storage for the last sent event */
	event_storage_clear(qq);

	/* Clean up all allocated raw events */
	while ((raw = RB_ROOT(&qq->raw_event_by_time)) != NULL) {
		raw_event_remove(qq, raw);
		raw_event_free(raw);
	}
	if (!RB_EMPTY(&qq->raw_event_by_pidtime))
		qwarnx("raw_event trees not empty");
	/* Clean up all cached quark_processs */
	while ((qp = RB_ROOT(&qq->process_by_pid)) != NULL)
		process_cache_delete(qq, qp);
	/* Clean up all cached sockets */
	while ((qsk = RB_ROOT(&qq->socket_by_src_dst)) != NULL)
		socket_cache_delete(qq, qsk);
	/* Clean up backend */
	if (qq->queue_ops != NULL)
		qq->queue_ops->close(qq);
	/* Clean up qkube */
	if (qq->qkube != NULL) {
		kube_stop(qq);
		while ((pod = RB_ROOT(&qq->qkube->pod_by_uid)) != NULL)
			pod_delete(qq, pod);
		free(qq->qkube->node.name);
		free(qq->qkube->node.uid);
		free(qq->qkube->node.zone);
		free(qq->qkube->node.region);
		free(qq->qkube->node.provider);
		free(qq->qkube->node.project);
		free(qq->qkube->node.project_id);
		free(qq->qkube->node.cluster_name);
		free(qq->qkube->node.cluster_uid);
		free(qq->qkube->node.cluster_version);
		free(qq->qkube->buf);
		free(qq->qkube);
		qq->qkube = NULL;
	}
	/* Clean up passwd entries */
	while ((qpw = RB_ROOT(&qq->passwd_by_uid)) != NULL) {
		RB_REMOVE(passwd_by_uid, &qq->passwd_by_uid, qpw);
		free(qpw->name);
		free(qpw);
	}
	/* Clean up group entries */
	while ((qgrp = RB_ROOT(&qq->group_by_gid)) != NULL) {
		RB_REMOVE(group_by_gid, &qq->group_by_gid, qgrp);
		free(qgrp->name);
		free(qgrp);
	}
	/* Clean up sysinfo */
	quark_sysinfo_delete(&qq->sysinfo);
	/* Close epollfd */
	if (qq->epollfd != -1) {
		if (close(qq->epollfd) == -1)
			qwarn("close epollfd");
		qq->epollfd = -1;
	}
}

static int
can_aggregate_file(struct quark_queue *qq, struct raw_event *p, struct raw_event *c)
{
	struct quark_file	*pf, *cf;

	pf = p->file.quark_file;
	cf = c->file.quark_file;

	if (pf->inode != cf->inode)
		return (0);
	/*
	 * Maybe we should escape uid/gid/mode, makes it possible to hide stuff
	 */
	if (pf->op_mask & (QUARK_FILE_OP_REMOVE|QUARK_FILE_OP_MOVE))
		return (0);
	if ((pf->op_mask & (QUARK_FILE_OP_CREATE|QUARK_FILE_OP_MODIFY)) &&
	    (cf->op_mask & (QUARK_FILE_OP_MODIFY|QUARK_FILE_OP_REMOVE)))
		return (1);

	return (0);
}

static int
can_aggregate(struct quark_queue *qq, struct raw_event *p, struct raw_event *c)
{
	int			 kind;
	struct raw_event	*agg;

	/* Different pids can't aggregate */
	if (p->pid != c->pid)
		return (0);

	if (p->type >= RAW_NUM_TYPES || c->type >= RAW_NUM_TYPES ||
	    p->type <= RAW_INVALID || c->type <= RAW_INVALID) {
		qwarnx("type out of bounds p=%d c=%d", p->type, c->type);
		return (0);
	}

	kind = qq->agg_matrix[p->type][c->type];

	switch (kind) {
	case AGG_NONE:
		return (0);
	case AGG_MULTI:
		return (1);
	case AGG_SINGLE:
		TAILQ_FOREACH(agg, &p->agg_queue, agg_entry) {
			if (agg->type == c->type)
				return (0);
		}
		return (1);
	case AGG_CUSTOM:
		if (p->type == RAW_FILE && c->type == RAW_FILE)
			return (can_aggregate_file(qq, p, c));
		return (0);
	default:
		qwarnx("unhandle agg kind %d", kind);
		return (0);
	}
}

static void
quark_queue_aggregate(struct quark_queue *qq, struct raw_event *min)
{
	struct raw_event	*next, *aux;
	int			 agg;

	agg = 0;

	next = RB_NEXT(raw_event_by_pidtime, &qq->raw_event_by_pidtime,
	    min);
	while (next != NULL) {
		if (!can_aggregate(qq, min, next))
			break;
		aux = next;
		next = RB_NEXT(raw_event_by_pidtime,
		    &qq->raw_event_by_pidtime, next);
		raw_event_remove(qq, aux);
		TAILQ_INSERT_TAIL(&min->agg_queue, aux, agg_entry);
		agg++;
	}

	if (agg)
		qq->stats.aggregations++;
	else
		qq->stats.non_aggregations++;
}

int
quark_queue_populate(struct quark_queue *qq)
{
	return (qq->queue_ops->populate(qq));
}

static struct raw_event *
quark_queue_pop_raw(struct quark_queue *qq)
{
	struct raw_event	*min;
	u64			 now;

	/*
	 * We populate before draining so we can have a fuller tree for
	 * aggregation.
	 */
	(void)quark_queue_populate(qq);

	now = now64();
	min = RB_MIN(raw_event_by_time, &qq->raw_event_by_time);
	if (min == NULL || !raw_event_expired(qq, min, now)) {
		/* qq->idle++; */
		return (NULL);
	}

	quark_queue_aggregate(qq, min);
	/* qq->min = RB_NEXT(raw_event_by_time, &qq->raw_event_by_time, min); */
	raw_event_remove(qq, min);

	return (min);
}

static const struct quark_event *
raw_event_sock(struct quark_queue *qq, struct raw_event *raw)
{
	struct quark_event	*qev;
	struct quark_socket	*qsk;
	struct raw_sock_conn	*conn;

	conn = &raw->sock_conn;
	qev = &qq->event_storage;

	qsk = socket_cache_lookup(qq, &conn->local, &conn->remote);

	switch (conn->conn) {
	case SOCK_CONN_ACCEPT:	/* FALLTHROUGH */
	case SOCK_CONN_CONNECT:
		/*
		 * We found an existing socket, this has two possibilities:
		 * 1 - We lost the original CLOSE.
		 * 2 - We just got it from scraping /proc, but since the rings
		 *     were opened during scraping, we end up seeing it "twice".
		 */
		if (qsk != NULL) {
			/*
			 * If we learned it by scraping, supress it.
			 */
			if (qsk->pid_origin == raw->pid && qsk->conn_origin == SOCK_CONN_SCRAPE) {
				qsk->pid_last_use = qsk->pid_origin;
				return (NULL);
			}

			/*
			 * This probably means we lost the CLOSE, so evict the
			 * old one.
			 */
			qwarnx("evicting possibly old socket");
			socket_cache_delete(qq, qsk);
			qsk = NULL;
		}

		qsk = socket_alloc_and_insert(qq, &conn->local, &conn->remote,
		    conn->conn, 0, 0, raw->pid, raw->time);
		if (qsk == NULL) {
			qwarn("socket_alloc");
			return (NULL);
		}
		qev->events = QUARK_EV_SOCK_CONN_ESTABLISHED;
		break;
	case SOCK_CONN_CLOSE:
		/*
		 * If there was no previous socket, good chances we lost ACCEPT
		 * or CONNECT, let the user decide what to do, but mark it as
		 * deleted anyway.
		 */
		if (qsk == NULL) {
			qsk = socket_alloc_and_insert(qq, &conn->local, &conn->remote,
			    conn->conn, conn->bytes_received, conn->bytes_sent,
			    raw->pid, raw->time);
			if (qsk == NULL) {
				qwarn("socket_alloc");
				return (NULL);
			}
		}

		if (qsk->close_time == 0)
			qsk->close_time = raw->time;
		qsk->bytes_received = conn->bytes_received;
		qsk->bytes_sent = conn->bytes_sent;

		gc_mark(qq, &qsk->gc, GC_SOCKET);
		qev->events = QUARK_EV_SOCK_CONN_CLOSED;

		break;
	default:
		qwarnx("invalid conn->conn %d\n", conn->conn);
		return (NULL);
	}

	qsk->pid_last_use = raw->pid;

	qev->socket = qsk;
	qev->process = quark_process_lookup(qq, qsk->pid_origin);

	return (qev);
}

static const struct quark_event *
raw_event_packet(struct quark_queue *qq, struct raw_event *raw)
{
	struct quark_event	*qev;

	if (raw->packet.quark_packet == NULL) {
		qwarnx("quark_packet is null");

		return (NULL);
	}

	qev = &qq->event_storage;

	qev->events = QUARK_EV_PACKET;
	qev->process = quark_process_lookup(qq, raw->pid);

	/* Steal the packet */
	qev->packet = raw->packet.quark_packet;
	raw->packet.quark_packet = NULL;

	return (qev);
}

static const struct quark_event *
raw_event_file(struct quark_queue *qq, struct raw_event *raw)
{
	struct quark_event	*qev;
	struct raw_event	*agg;
	u32			 op_mask;

	if (raw->file.quark_file == NULL) {
		qwarnx("quark_file is null");

		return (NULL);
	}

	qev = &qq->event_storage;

	qev->events = QUARK_EV_FILE;
	qev->process = quark_process_lookup(qq, raw->pid);

	/*
	 * File aggregation is basically joining op_mask and then using the last
	 * raw_event.
	 */
	op_mask = raw->file.quark_file->op_mask;
	TAILQ_FOREACH(agg, &raw->agg_queue, agg_entry) {
		op_mask |= agg->file.quark_file->op_mask;
		raw = agg;
	}

	/* Steal the file */
	raw->file.quark_file->op_mask = op_mask;
	qev->file = raw->file.quark_file;
	raw->file.quark_file = NULL;

	return (qev);
}

static const struct quark_event *
raw_event_ptrace(struct quark_queue *qq, struct raw_event *raw)
{
	struct quark_event	*qev;

	qev = &qq->event_storage;

	qev->events = QUARK_EV_PTRACE;
	qev->process = quark_process_lookup(qq, raw->pid);
	qev->ptrace = raw->ptrace.quark_ptrace;

	return (qev);
}

static const struct quark_event *
raw_event_module_load(struct quark_queue *qq, struct raw_event *raw)
{
	struct quark_event	*qev;

	qev = &qq->event_storage;

	qev->events = QUARK_EV_MODULE_LOAD;
	qev->process = quark_process_lookup(qq, raw->pid);
	/* Steal it */
	qev->module_load = raw->module_load.quark_module_load;
	raw->module_load.quark_module_load = NULL;

	return (qev);
}

static const struct quark_event *
raw_event_shm(struct quark_queue *qq, struct raw_event *raw)
{
	struct quark_event	*qev;

	qev = &qq->event_storage;

	qev->events = QUARK_EV_SHM;
	qev->process = quark_process_lookup(qq, raw->pid);
	/* Steal it */
	qev->shm = raw->shm.quark_shm;
	raw->shm.quark_shm = NULL;

	return (qev);
}

static const struct quark_event *
get_bypass_event(struct quark_queue *qq)
{
	struct quark_event	*qev;
	int			 n;

	qev = &qq->event_storage;

	/*
	 * Populate fills in qev
	 */
	qev->events = 0;
	qev->bypass = NULL;
	n = quark_queue_populate(qq);
	if (n <= 0)
		return (NULL);

	return (qev);
}

const struct quark_event *
quark_queue_get_event(struct quark_queue *qq)
{
	struct raw_event		*raw;
	const struct quark_event	*qev;

	if (qq->qkube != NULL)
		kube_read_events(qq);

	if (qq->flags & QQ_BYPASS)
		return (get_bypass_event(qq));

	qev = NULL;
	event_storage_clear(qq);

	/* Get a quark_event out of a raw_event */
	if ((raw = quark_queue_pop_raw(qq)) != NULL) {
		switch (raw->type) {
		case RAW_EXEC:			/* FALLTHROUGH */
		case RAW_WAKE_UP_NEW_TASK:	/* FALLTHROUGH */
		case RAW_EXIT_THREAD:		/* FALLTHROUGH */
		case RAW_COMM:			/* FALLTHROUGH */
		case RAW_EXEC_CONNECTOR:
			qev = raw_event_process(qq, raw);
			break;
		case RAW_SOCK_CONN:
			qev = raw_event_sock(qq, raw);
			break;
		case RAW_PACKET:
			qev = raw_event_packet(qq, raw);
			break;
		case RAW_FILE:
			qev = raw_event_file(qq, raw);
			break;
		case RAW_PTRACE:
			qev = raw_event_ptrace(qq, raw);
			break;
		case RAW_MODULE_LOAD:
			qev = raw_event_module_load(qq, raw);
			break;
		case RAW_SHM:
			qev = raw_event_shm(qq, raw);
			break;
		default:
			qwarnx("unhandled raw->type: %d", raw->type);
			break;
		}

		raw_event_free(raw);
	}

	if (qev != NULL && qq->qkube != NULL)
		link_kube_data(qq, (struct quark_process *)qev->process);

	/* GC all processes and sockets that exited after some grace time */
	gc_collect(qq);

	return (qev);
}

int
quark_start_kube_talker(const char *kube_config, pid_t *pid)
{
	int	pipefd[2];

	if (kube_config == NULL || pid == NULL)
		return (errno = EINVAL, -1);

	*pid = -1;
	if ((pipe(pipefd)) == -1)
		return (-1);

	if ((*pid = fork()) == -1) {
		close(pipefd[0]);
		close(pipefd[1]);
		return (-1);
	}

	/* parent */
	if (*pid != 0) {
		close(pipefd[1]);

		return (pipefd[0]);
	}

	/* child */
	close(pipefd[0]);
	if (dup2(pipefd[1], STDOUT_FILENO) == -1)
		err(1, "dup2");

	if (qclosefrom(3, -1) == -1) {
		qwarn("qclosefrom");
		qwarnx("not closing child descriptors");
	}

	if (execlp("quark-kube-talker", "quark-kube-talker",
	    "-m", "-K", kube_config, (char *)NULL) == -1)
		err(1, "execlp quark-kube-talker");

	return (0);		/* NOTREACHED */
}
