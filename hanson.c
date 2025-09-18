// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2025 Elastic NV */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quark.h"

int	hanson_add_ascii(struct hanson *, char);

static inline size_t
hanson_space_left(struct hanson *h)
{
	return ((h->buf + h->buf_len) - h->buf_w);
}

/*
 * Don't make it inline or static, otherwise code grows too much, this is the
 * slow path, we lose around 20% perf if we inline here.
 */
int	hanson_grow(struct hanson *h);

int
hanson_grow(struct hanson *h)
{
	char	*new_buf;

	if (h->error)
		return (-1);
	new_buf = reallocarray(h->buf, h->buf_len, 2);
	if (unlikely(new_buf == NULL)) {
		h->error = 1;
		return (-1);
	}
	h->buf_w = new_buf + (h->buf_w - h->buf);
	h->buf = new_buf;
	h->buf_len *= 2;	/* keep in sync with reallocarray */

	return (0);
}

static inline int
hanson_add(struct hanson *h, void *data, size_t data_len)
{
again:
	if (likely(hanson_space_left(h) >= data_len)) {
		    memcpy(h->buf_w, data, data_len);
		    h->buf_w += data_len;
	} else {
		if (hanson_grow(h) == -1)
			return (-1);
		goto again;
	}

	return (0);
}

static inline int
hanson_add_ascii_inline(struct hanson *h, char c) /* inline this is significant */
{
	return (hanson_add(h, &c, 1));
}

static inline int
hanson_maybe_first(struct hanson *h, int *first)
{
	int	r = 0;

	if (first != NULL) {
		if (*first == 0)
			r |= hanson_add_ascii_inline(h, ',');
		*first = 0;
	}

	return (r);
}

/*
 * Don't change to char, otherwise it will sign extend on wide characters
 */
static inline int
is_escape_char(u_char c)
{
	int	v = 0;

	switch (c) {
	case '\\':	/* FALLTHROUGH */
	case '\"':	/* FALLTHROUGH */
	case '\b':	/* FALLTHROUGH */
	case '\f':	/* FALLTHROUGH */
	case '\n':	/* FALLTHROUGH */
	case '\r':	/* FALLTHROUGH */
	case '\t':	/* FALLTHROUGH */
		v = 1;
		break;
	default:
		if (c < 32)
			v = 1;
		break;
	}

	return (v);
}

static int
hanson_add_string_escaped(struct hanson *h, char *s)
{
	int	 r = 0, len, c;
	char	*p;
	char	 unicode_buf[16];

	for (p = s; *p != 0; p++) {
		c = is_escape_char(*p);

		if (!c) {
			hanson_add_ascii_inline(h, *p);
			continue;
		}

		hanson_add_ascii_inline(h, '\\');
		switch (*p) {
		case '\\':
			r |= hanson_add_ascii_inline(h, '\\');
			break;
		case '\"':
			r |= hanson_add_ascii_inline(h, '\"');
			break;
		case '\b':
			r |= hanson_add_ascii_inline(h, 'b');
			break;
		case '\f':
			r |= hanson_add_ascii_inline(h, 'f');
			break;
		case '\n':
			r |= hanson_add_ascii_inline(h, 'n');
			break;
		case '\r':
			r |= hanson_add_ascii_inline(h, 'r');
			break;
		case '\t':
			r |= hanson_add_ascii_inline(h, 't');
			break;
		default:
			len = snprintf(unicode_buf, sizeof(unicode_buf),
			    "u%04x", (u_char)*p);
			if (likely(len > 0))
				r |= hanson_add(h, unicode_buf, len);
			else {
				h->error = 1;
				r = -1;
			}
			break;
		}
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
hanson_add_ascii(struct hanson *h, char c)
{
	return (hanson_add_ascii_inline(h, c));
}

int
hanson_add_string(struct hanson *h, char *s, int *first)
{
	int	 r = 0;
	char	*p;
	int	 need_escape;
	size_t	 len;

	r |= hanson_maybe_first(h, first);
	r |= hanson_add_ascii_inline(h, '"');

	need_escape = 0;
	for (p = s, len = 0; *p != 0; p++, len++) {
		if (unlikely(is_escape_char(*p))) {
			need_escape = 1;
			break;
		}
	}

	if (unlikely(need_escape))
		r |= hanson_add_string_escaped(h, s);
	else
		r |= hanson_add(h, s, len);

	r |= hanson_add_ascii_inline(h, '"');

	return (r);
}

int
hanson_add_integer(struct hanson *h, int64_t vs, int *first)
{
	/* 19 characters for the number + 1 for sign + 2 for paranoia */
	char	*p, *end, buf[22];
	int	 negative;
	u64	 v = vs;

	hanson_maybe_first(h, first);

	p = end = buf + sizeof(buf) - 2;

	if (unlikely((int64_t)v < 0)) {
		negative = 1;
		v *= -1;
	} else
		negative = 0;

	do {
		*(--p) = (v % 10) + '0';
		v /= 10;
	} while (v > 0);

	if (unlikely(negative))
		*(--p) = '-';

//	printf("p=%s\n", p);

	return (hanson_add(h, p, end - p));
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
	r |= hanson_add_ascii_inline(h, ':');
	r |= hanson_add_string(h, v, NULL);

	return (r);
}

int
hanson_add_key_value_int(struct hanson *h, char *k, int64_t v, int *first)
{
	int	r = 0;

	r |= hanson_add_string(h, k, first);
	r |= hanson_add_ascii_inline(h, ':');
	r |= hanson_add_integer(h, v, NULL);

	return (r);
}

int
hanson_add_key_value_bool(struct hanson *h, char *k, int v, int *first)
{
	int	r = 0;

	r |= hanson_add_string(h, k, first);
	r |= hanson_add_ascii_inline(h, ':');
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
	return (hanson_add_ascii_inline(h, ']'));
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
	return (hanson_add_ascii_inline(h, '}'));
}

int
hanson_open(struct hanson *h)
{
	bzero(h, sizeof(*h));

	h->buf_len = 1 << 14;
	if ((h->buf = malloc(h->buf_len)) == NULL)
		return (-1);
	h->buf_w = h->buf;
	if (hanson_add_ascii_inline(h, '{') == -1) {
		free(h->buf);

		return (-1);
	}

	return (0);
}

int
hanson_close(struct hanson *h, char **buf, size_t *buf_len)
{
	int	r = 0;

	r |= hanson_add_ascii_inline(h, '}');
	r |= hanson_add_ascii_inline(h, 0);
	if (h->error) {
		free(h->buf);
		r = -1;
	} else {
		*buf = h->buf;
		*buf_len = h->buf_w - h->buf;
	}
	h->buf = NULL;
	h->buf_w = NULL;
	h->buf_len = 0;

	return (r);
}
