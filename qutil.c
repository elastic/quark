#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "quark.h"

ssize_t
qread(int fd, void *buf, size_t count)
{
	ssize_t n;

again:
	n = read(fd, buf, count);
	if (n == -1) {
		if (errno == EINTR)
			goto again;
		warn("read");
		return (-1);
	} else if (n == 0) {
		warnx("read unexpected EOF");
		return (-1);
	}

	return (n);
}

int
qwrite(int fd, const void *buf, size_t count)
{
	ssize_t n;
	const char *p;

	for (p = buf; count != 0; p += n, count -= n) {
	again:
		n = write(fd, p, count);
		if (n == -1) {
			if (errno == EINTR)
				goto again;
			return (-1);
		} else if (n == 0)
			return (errno = EPIPE, -1);
	}

	return (0);
}

void
qstr_init(struct qstr *qstr)
{
	qstr->p = qstr->small;
}

int
qstr_ensure(struct qstr *qstr, size_t n)
{
	if (n > sizeof(qstr->small)) {
		qstr->p = malloc(n);
		if (qstr->p == NULL)
			return (-1);
	}

	return (0);
}

int
qstr_copy_data_loc(struct qstr *qstr,
    struct perf_record_sample *sample, struct perf_sample_data_loc *data_loc)
{
	/* size includes NUL */
	if (qstr_ensure(qstr, data_loc->size) == -1)
		return (-1);
	memcpy(qstr->p, sample->data + data_loc->offset, data_loc->size);

	return (data_loc->size);
}

int
qstr_memcpy(struct qstr *qstr, void *src, size_t len)
{
	if (qstr_ensure(qstr, len) == -1)
		return (-1);
	memcpy(qstr->p, src, len);

	return (0);
}

#if 0
ssize_t
qstr_strlcpy(struct qstr *qstr, const char *src)
{
	ssize_t slen = strlen(src);

	qstr_ensure(qstr, slen + 1);
	memcpy(qstr->p, src, slen);
	qstr->p[slen] = 0;

	return (slen);
}
#endif
void
qstr_free(struct qstr *qstr)
{
	if (qstr->p == qstr->small)
		return;

	free(qstr->p);
}

