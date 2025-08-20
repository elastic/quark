// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2025 Elastic NV */

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>
#include <time.h>

#include "quark.h"

RB_PROTOTYPE(label_tree, label_node, entry, label_node_cmp); /* XXXX */

static char *
ctime_chomped(const time_t *t, char buf[26])
{
	char	*p, *p1;

	p = ctime_r(t, buf);

	if (p != NULL) {
		p1 = strchr(buf, '\n');
		if (p1 != NULL)
			*p1 = 0;
	}

	return (p);
}

/* XXX Hackish!! */
static int
is_interactive(const struct quark_process *qp)
{
	u32	major, minor;

	major = qp->proc_tty_major;
	minor = qp->proc_tty_minor;

	if (major >= 136 && major <= 143)
		return (1);
	if (major == 4) {
		if (minor <= 63)
			return (1);
		else if (minor > 63 && minor <= 255)
			return (1);
	}

	return (0);
}

static int
ecs_event_action(struct hanson *h, const struct quark_event *qev, int *first)
{
	int	fork, exec, exit, conn_est, conn_closed;
	int	packet, file;
	char	buf[64];
	int	r;
	

	r = 0;
	*buf = 0;

	fork = !!(qev->events & QUARK_EV_FORK);
	exec = !!(qev->events & QUARK_EV_EXEC);
	exit = !!(qev->events & QUARK_EV_EXIT);
	conn_est = !!(qev->events & QUARK_EV_SOCK_CONN_ESTABLISHED);
	conn_closed = !!(qev->events & QUARK_EV_SOCK_CONN_CLOSED);
	packet = !!(qev->events & QUARK_EV_PACKET);
	file = !!(qev->events & QUARK_EV_FILE);

	if (fork || exec || exit) {
		strlcat(buf, "process", sizeof(buf));
		if (fork)
			strlcat(buf, "-forked", sizeof(buf));
		if (exec)
			strlcat(buf, "-executed", sizeof(buf));
		if (exit)
			strlcat(buf, "-exited", sizeof(buf));

	} else if (conn_est || conn_closed) {
		strlcat(buf, "connection", sizeof(buf));
		if (conn_est)
			strlcat(buf, "-established", sizeof(buf));
		if (conn_closed)
			strlcat(buf, "-closed", sizeof(buf));

	} else if (packet) {
		strlcat(buf, "packet", sizeof(buf));
		if (qev->packet->origin == QUARK_PACKET_ORIGIN_DNS)
			strlcat(buf, "-dns", sizeof(buf));
		if (qev->packet->direction == QUARK_PACKET_DIR_INGRESS)
			strlcat(buf, "-received", sizeof(buf));
		else if (qev->packet->direction == QUARK_PACKET_DIR_EGRESS)
			strlcat(buf, "-sent", sizeof(buf));


	} else if (file) {
		u32 mask = qev->file->op_mask;

		strlcat(buf, "file", sizeof(buf));
		if (mask & QUARK_FILE_OP_CREATE)
			strlcat(buf, "-created", sizeof(buf));
		if (mask & QUARK_FILE_OP_MODIFY)
			strlcat(buf, "-written", sizeof(buf));
		if (mask & QUARK_FILE_OP_MOVE)
			strlcat(buf, "-renamed", sizeof(buf));
		if (mask & QUARK_FILE_OP_REMOVE)
			strlcat(buf, "-deleted", sizeof(buf));

	} else {
		strlcat(buf, "unknown", sizeof(buf));
		r = -1;
	}

	hanson_add_key_value(h, "action", buf, first);

	return (r);
}

static int
ecs_process_user(struct hanson *h, const struct quark_process *qp, int *first)
{
	if (qp == NULL || !(qp->flags & QUARK_F_PROC))
		return (-1);

	hanson_add_object(h, "user", first);
	{
		int	user_first = 1;

		/*
		 * NOTE process.user.id and process.user.group.id are
		 * effective, not real.
		 */
		hanson_add_key_value_int(h, "id", qp->proc_euid,
		    &user_first);
		/* XXX no username */

		/* process.user.group.* */
		hanson_add_object(h, "group", &user_first);
		{
			int	group_first = 1;

			hanson_add_key_value_int(h, "id", qp->proc_egid,
			    &group_first);
		}
		hanson_close_object(h);

		/* process.real_user.*/
		hanson_add_object(h, "real_user", &user_first);
		{
			int	real_first = 1;

			hanson_add_key_value_int(h, "id", qp->proc_uid,
			    &real_first);
		}
		hanson_close_object(h);

		/* process.real_group.* */
		hanson_add_object(h, "real_group", &user_first);
		{
			int	real_group_first = 1;

			hanson_add_key_value_int(h, "id", qp->proc_gid,
			    &real_group_first);
			/* XXX no effective name */
		}
		hanson_close_object(h);

		/* process.saved_user.*/
		hanson_add_object(h, "saved_user", &user_first);
		{
			int	saved_first = 1;

			hanson_add_key_value_int(h, "id", qp->proc_uid,
			    &saved_first);
		}
		hanson_close_object(h);

		/* process.saved_group.* */
		hanson_add_object(h, "saved_group", &user_first);
		{
			int	saved_group_first = 1;

			hanson_add_key_value_int(h, "id", qp->proc_gid,
			    &saved_group_first);
			/* XXX no effective name */
		}
		hanson_close_object(h);
	}
	hanson_close_object(h);

	return (0);
}

static int
ecs_process_tty(struct hanson *h, const struct quark_process *qp, int *first)
{
	hanson_add_object(h, "tty", first);
	{
		int	tty_first = 1;

		hanson_add_object(h, "char_device", &tty_first);
		{
			int	char_device_first = 1;

			hanson_add_key_value_int(h, "major", qp->proc_tty_major,
			    &char_device_first);
			hanson_add_key_value_int(h, "minor", qp->proc_tty_minor,
			    &char_device_first);
		}
		hanson_close_object(h);
	}
	hanson_close_object(h);

	return (0);
}

static int
ecs_container(struct hanson *h, const struct quark_event *qev, int *first)
{
	const struct quark_process	*qp;
	struct quark_container		*container;
	struct quark_pod		*pod;
	struct label_node		*label;

	if (qev->process == NULL || qev->process->container == NULL ||
	    qev->process->container->pod == NULL)
		return (-1);

	qp = qev->process;
	container = qp->container;
	pod = container->pod;

	hanson_add_key_value(h, "id", container->container_id, first);
	hanson_add_key_value(h, "name", container->name, first);
	/* docker is the only one we support */
	hanson_add_key_value(h, "runtime", "docker", first);

	/* container.label.* */
	hanson_add_object(h, "labels", first);
	{
		int	label_first = 1;

		RB_FOREACH(label, label_tree, &pod->labels) {
			hanson_add_key_value(h, label->key, label->value, &label_first);
		}
	}
	hanson_close_object(h);

	/* container image */
	hanson_add_object(h, "image", first);
	{
		int	image_first = 1;

		hanson_add_key_value(h, "name", container->image, &image_first);
//		hanson_add_key_value(h, "id", container->image_id, &image_first);
	}
	hanson_close_object(h);

	return (0);
}

static int
ecs_orchestrator(struct hanson *h, const struct quark_event *qev, int *first)
{
	const struct quark_process	*qp;
	struct quark_container		*container;
	struct quark_pod		*pod;
	struct label_node		*label;

	if (qev->process == NULL || qev->process->container == NULL ||
	    qev->process->container->pod == NULL)
		return (-1);

	qp = qev->process;
	container = qp->container;
	pod = container->pod;

	hanson_add_object(h, "resource", first);
	{
		int	resource_first = 1;

		hanson_add_key_value(h, "type", "pod", &resource_first);
		hanson_add_key_value(h, "name", pod->name, &resource_first);
		hanson_add_key_value(h, "namespace", pod->namespace,
		    &resource_first);

		hanson_add_object(h, "labels", &resource_first);
		{
			int	label_first = 1;

			RB_FOREACH(label, label_tree, &pod->labels) {
				hanson_add_key_value(h,
				    label->key, label->value, &label_first);
			}
		}
		hanson_close_object(h);
	}
	hanson_close_object(h);

	return (0);
}

static int
ecs_process(struct hanson *h, const struct quark_event *qev, int *first)
{
	const struct quark_process	*qp;

	qp = qev->process;

	hanson_add_key_value_int(h, "pid", qp->pid, first);

	if (qp->flags & QUARK_F_PROC) {
		char	start_time[32];
		time_t 	start_sec;

		hanson_add_key_value(h, "entity_id", (char *)qp->proc_entity_id,
		    first);

		start_sec = NS_TO_S(qp->proc_time_boot);
		if (ctime_chomped(&start_sec, start_time) != NULL)
			hanson_add_key_value(h, "start", start_time, first);
		hanson_add_key_value_bool(h, "interactive", is_interactive(qp),
		    first);
		/* process.user.* */
		ecs_process_user(h, qp, first);
		/* process.tty.* */
		ecs_process_tty(h, qp, first);
	}

	if (qp->flags & QUARK_F_COMM)
		hanson_add_key_value(h, "name", (char *)qp->comm, first);

	if (qp->flags & QUARK_F_FILENAME)
		hanson_add_key_value(h, "executable", qp->filename, first);

	if (qp->flags & QUARK_F_CMDLINE) {
		int	count = 0;

		hanson_add_array(h, "command_line", first);
		{
			struct quark_cmdline_iter	 qcmdi;
			const char			*arg;
			int				 cmdline_first = 1;

			quark_cmdline_iter_init(&qcmdi, qp->cmdline, qp->cmdline_len);
			while ((arg = quark_cmdline_iter_next(&qcmdi)) != NULL) {
				hanson_add_string(h, (char *)arg,
				    &cmdline_first);
				count++;
			}
		}
		hanson_close_array(h);
		hanson_add_key_value_int(h, "args_count", count, first);
	}

	if (qp->flags & QUARK_F_CWD)
		hanson_add_key_value(h, "working_directory", qp->cwd, first);

	if (qp->flags & QUARK_F_EXIT) {
		char	end_time[32];
		time_t 	end_sec;

		hanson_add_key_value(h, "entity_id", (char *)qp->proc_entity_id,
		    first);

		end_sec = NS_TO_S(qp->exit_time_event);
		if (ctime_chomped(&end_sec, end_time) != NULL)
			hanson_add_key_value(h, "end", end_time, first);

		hanson_add_key_value_int(h, "exit_code", qp->exit_code, first);
	}

	return (0);
}

static int
ecs_socket(struct hanson *h, const struct quark_event *qev, int *first)
{
	const struct quark_socket	*qsk;
	char				 buf[INET6_ADDRSTRLEN];

	qsk = qev->socket;

	/* source.* */
	hanson_add_object(h, "source", first);
	{
		int	source_first = 1;

		if (inet_ntop(qsk->local.af, &qsk->local.addr6,
		    buf, sizeof(buf)) != NULL) {
			hanson_add_key_value(h, "address", buf, &source_first);
			hanson_add_key_value(h, "ip", buf, &source_first);
			hanson_add_key_value_int(h, "port", ntohs(qsk->local.port), &source_first);
		}
	}
	hanson_close_object(h);

	/* destination.* */
	hanson_add_object(h, "destination", first);
	{
		int	destination_first = 1;

		if (inet_ntop(qsk->remote.af, &qsk->remote.addr6,
		    buf, sizeof(buf)) != NULL) {
			hanson_add_key_value(h, "address", buf, &destination_first);
			hanson_add_key_value(h, "ip", buf, &destination_first);
			hanson_add_key_value_int(h, "port", ntohs(qsk->remote.port), &destination_first);
		}
	}
	hanson_close_object(h);

	/* network.* */
	hanson_add_object(h, "network", first);
	{
		int	 network_first = 1;
		char	*afs;

		/* we only have tcp for now */
		hanson_add_key_value(h, "transport", "tcp", &network_first);

		switch(qsk->local.af) {
		case AF_INET:
			afs = "ipv4";
			break;
		case AF_INET6:
			afs = "ipv6";
			break;
		default:
			afs = "unknown";
			break;
		}

		hanson_add_key_value(h, "type", afs, &network_first);
		/* XXX missing direction */
	}
	hanson_close_object(h);

	return (0);
}

static int
ecs_file(struct hanson *h, const struct quark_event *qev, int *first)
{
	struct quark_file	*file = qev->file;
	char			 buf[32];
	time_t			 ctime, mtime, atime;

	hanson_add_key_value(h, "path", (char *)file->path, first);
	hanson_add_key_value_int(h, "inode", file->inode, first);
	hanson_add_key_value_int(h, "size", file->size, first);
	hanson_add_key_value_int(h, "uid", file->uid, first);
	hanson_add_key_value_int(h, "gid", file->gid, first);

	snprintf(buf, sizeof(buf), "0%o", file->mode);
	hanson_add_key_value(h, "mode", buf, first);

	ctime = NS_TO_S(file->ctime);
	mtime = NS_TO_S(file->mtime);
	atime = NS_TO_S(file->atime);
	if (ctime_chomped(&ctime, buf) != NULL)
		hanson_add_key_value(h, "ctime", buf, first);
	if (ctime_chomped(&mtime, buf) != NULL)
		hanson_add_key_value(h, "mtime", buf, first);
	if (ctime_chomped(&atime, buf) != NULL)
		hanson_add_key_value(h, "accessed", buf, first);


	return (0);
}

int
quark_event_to_ecs(const struct quark_event *qev, char **buf, size_t *buf_len)
{
	struct hanson	h;
	int		top_first;

	if (qev->events == QUARK_EV_BYPASS)
		return (errno = EINVAL, -1);

	if (hanson_open(&h) == -1)
		return (-1);

	top_first = 1;
	hanson_add_object(&h, "event", &top_first);
	{
		int	event_first = 1;

		ecs_event_action(&h, qev, &event_first);
		hanson_add_key_value(&h, "kind", "event", &event_first);
	}
	hanson_close_object(&h);

	if (qev->process != NULL) {
		hanson_add_object(&h, "process", &top_first);
		{
			int	process_first = 1;

			ecs_process(&h, qev, &process_first);
		}
		hanson_close_object(&h);

		if (qev->process->container != NULL) {
			hanson_add_object(&h, "container", &top_first);
			{
				int	container_first = 1;

				ecs_container(&h, qev, &container_first);
			}
			hanson_close_object(&h);

			hanson_add_object(&h, "orchestrator", &top_first);
			{
				int	orchestrator_first = 1;

				ecs_orchestrator(&h, qev, &orchestrator_first);
			}
			hanson_close_object(&h);
		}
	}

	if (qev->socket != NULL)
		ecs_socket(&h, qev, &top_first);

	if (qev->file != NULL) {
		hanson_add_object(&h, "file", &top_first);
		{
			int	file_first = 1;

			ecs_file(&h, qev, &file_first);
		}
		hanson_close_object(&h);
	}

	if (hanson_close(&h, buf, buf_len) == -1)
		return (-1);

	return (0);
}
