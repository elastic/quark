// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2025 Elastic NV */

#include <errno.h>

#include "quark.h"

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
ecs_process(struct hanson *h, const struct quark_event *qev, int *first)
{
	const struct quark_process	*qp;

	qp = qev->process;

	if (qp == NULL)
		return (0);

	if (qp->flags & QUARK_F_COMM)
		hanson_add_key_value(h, "name", (char *)qp->comm, first);

	if (qp->flags & QUARK_F_CMDLINE) {
		char buf[1024];
	}

	return (0);
}

int
quark_event_to_ecs(const struct quark_event *qev, char **buf, size_t *buf_len)
{
	struct hanson	h;
	int		top_first;
	/* struct quark_process	*qp; */

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
