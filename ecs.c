// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2025 Elastic NV */

#include <errno.h>

#include "quark.h"

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

		hanson_add_key_value_int(h, "id", qp->proc_uid,
		    &user_first);
		/* XXX no username */

		/* process.user.group.* */
		hanson_add_object(h, "group", &user_first);
		{
			int	group_first = 1;

			hanson_add_key_value_int(h, "id", qp->proc_gid,
			    &group_first);
		}
		hanson_close_object(h);

		/* process.user.effective.*/
		hanson_add_object(h, "effective", &user_first);
		{
			int	eff_first = 1;

			hanson_add_key_value_int(h, "id", qp->proc_euid,
			    &eff_first);

			/* process.user.effective.group.* */
			hanson_add_object(h, "group", &eff_first);
			{
				int	eff_group_first = 1;

				hanson_add_key_value_int(h, "id", qp->proc_egid,
				    &eff_group_first);
				/* XXX no effective name */
			}
			hanson_close_object(h);
		}
		hanson_close_object(h);

		/* process.user.saved.* */
		hanson_add_object(h, "saved", &user_first);
		{
			int	saved_first = 1;

			hanson_add_key_value_int(h, "id", qp->proc_suid,
			    &saved_first);

			/* process.user.saved.group.* */
			hanson_add_object(h, "group", &saved_first);
			{
				int	saved_group_first = 1;

				hanson_add_key_value_int(h, "id",
				    qp->proc_sgid, &saved_group_first);
				/* XXX no group name */
			}
			hanson_close_object(h);
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

	if (qp == NULL)
		return (0);

	hanson_add_key_value_int(h, "pid", qp->pid, first);

	if (qp->flags & QUARK_F_PROC) {
		hanson_add_key_value(h, "entity_id", (char *)qp->proc_entity_id,
		    first);
		hanson_add_key_value_bool(h, "interactive", is_interactive(qp),
		    first);
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

	if (qp->flags & QUARK_F_CWD) {
		hanson_add_key_value(h, "working_directory", qp->cwd, first);
	}

	if (qp->flags & QUARK_F_EXIT) {
		hanson_add_key_value_int(h, "exit_code", qp->exit_code, first);
	}

	/* process.user.* */
	if (qp->flags & QUARK_F_PROC) {
		hanson_add_key_value(h, "entity_id", (char *)qp->proc_entity_id,
		    first);
		hanson_add_key_value_bool(h, "interactive", is_interactive(qp),
		    first);
		ecs_process_user(h, qp, first);
	}

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
	}

	if (hanson_close(&h, buf, buf_len) == -1)
		return (-1);

	return (0);
}
