// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2025 Elastic NV */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quark.h"

static int
hanson_add(struct hanson *h, void *data, size_t data_len)
{
	size_t	r;

	r = fwrite(data, 1, data_len, h->stream);
	if (unlikely(r != data_len || ferror(h->stream))) {
		h->error = 1;
		return (-1);
	}

	return (0);
}

static int
hanson_maybe_first(struct hanson *h, int *first)
{
	int	r = 0;

	if (first != NULL) {
		if (*first == 0)
			r |= hanson_add_ascii(h, ',');
		*first = 0;
	}

	return (r);
}

static int
hanson_add_string_lead(struct hanson *h, char *s, char *lead)
{
	int	r = 0;

	r |= hanson_add_string(h, s, NULL);
	r |= hanson_add(h, lead, strlen(lead));

	return (r);
}

int
hanson_add_ascii(struct hanson *h, int c)
{
	int	r = 0;
	char	c8;

	c8 = c & 0xff;
	r |= hanson_add(h, &c8, 1);

	return (r);
}

int
hanson_add_string(struct hanson *h, char *s, int *first)
{
	int	r = 0;

	r |= hanson_maybe_first(h, first);
	r |= hanson_add_ascii(h, '"');
	r |= hanson_add(h, s, strlen(s));
	r |= hanson_add_ascii(h, '"');

	return (r);
}

int
hanson_add_integer(struct hanson *h, int64_t v)
{
	int		r = 0, len;
	char		buf[32];

	len = snprintf(buf, sizeof(buf), "%lld", (long long)v);
	/* if (len < 0) */
	/* 	r = -1; */
	r |= hanson_add(h, buf, len);

	return (r);
}

int
hanson_add_boolean(struct hanson *h, int v, int *first)
{
	int	 r = 0;
	char	*s = v ? "true" : "false";

	r |= hanson_maybe_first(h, first);
	r |= hanson_add(h, s, strlen(s));

	return (r);
}

int
hanson_add_key_value(struct hanson *h, char *k, char *v, int *first)
{
	int	r = 0;

	r |= hanson_add_string(h, k, first);
	r |= hanson_add_ascii(h, ':');
	r |= hanson_add_string(h, v, NULL);

	return (r);
}

int
hanson_add_key_value_int(struct hanson *h, char *k, int64_t v, int *first)
{
	int	r = 0;

	r |= hanson_add_string(h, k, first);
	r |= hanson_add_ascii(h, ':');
	r |= hanson_add_integer(h, v);

	return (r);
}

int
hanson_add_key_value_bool(struct hanson *h, char *k, int v, int *first)
{
	int	r = 0;

	r |= hanson_add_string(h, k, first);
	r |= hanson_add_ascii(h, ':');
	r |= hanson_add_boolean(h, v, NULL);

	return (r);
}

int
hanson_add_array(struct hanson *h, char *name, int *first)
{
	int	r = 0;

	r |= hanson_maybe_first(h, first);
	r |= hanson_add_string_lead(h, name, ":[");

	return (r);
}

int
hanson_close_array(struct hanson *h)
{
	return (hanson_add_ascii(h, ']'));
}

int
hanson_add_object(struct hanson *h, char *name, int *first)
{
	int	r = 0;

	r |= hanson_maybe_first(h, first);
	r |= hanson_add_string_lead(h, name, ":{");

	return (r);
}

int
hanson_close_object(struct hanson *h)
{
	return (hanson_add_ascii(h, '}'));
}

int
hanson_open(struct hanson *h)
{
	h->error = 0;
	h->buf_len = 0;
	h->buf = NULL;
	if ((h->stream = open_memstream(&h->buf, &h->buf_len)) == NULL)
		return (-1);
	if (hanson_add_ascii(h, '{') == -1) {
		fclose(h->stream);
		h->buf_len = 0;
		h->buf = NULL;
		h->stream = NULL;

		return (-1);
	}

	return (0);
}

int
hanson_close(struct hanson *h, char **buf, size_t *buf_len)
{
	int	r = 0;

	r |= hanson_add_ascii(h, '}');
	r |= hanson_add_ascii(h, 0);
	if (fclose(h->stream) != 0)
		h->error = 1;
	if (h->error) {
		free(h->buf);
		r = -1;
	} else {
		*buf = h->buf;
		*buf_len = h->buf_len;
	}
	h->buf = NULL;
	h->buf_len = 0;

	if (h->error)
		r = -1;

	return (r);
}
