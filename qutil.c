#include <ctype.h>		/* is_digit(3) */
#include <err.h>
#include <errno.h>
#include <fcntl.h>
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

/*
 * Safer readlinkat(2), guarantees termination and returns strlen(pathname) so
 * caller can check truncation, like strlcpy(). Compare to >= 0 if truncation is
 * acceptable.
 */
ssize_t
qreadlinkat(int dfd, const char *pathname, char *buf, size_t bufsiz)
{
	ssize_t n;

	if (bufsiz < 2)
		return (errno = EINVAL, -1);
	if ((n = readlinkat(dfd, pathname, buf, bufsiz - 1)) == -1)
		return (-1);
	buf[n] = 0;

	return (strlen(pathname));
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
qstr_memcpy(struct qstr *qstr, const void *src, size_t len)
{
	if (qstr_ensure(qstr, len) == -1)
		return (-1);
	memcpy(qstr->p, src, len);

	return (0);
}

int
qstr_strcpy(struct qstr *qstr, const char *src)
{
	return (qstr_memcpy(qstr, src, strlen(src) + 1));
}

void
qstr_free(struct qstr *qstr)
{
	if (qstr->p == qstr->small)
		return;

	free(qstr->p);
}

int
isnumber(const char *s)
{
	for (; *s != 0; s++) {
		if (!isdigit(*s))
			return (0);
	}

	return (1);
}

/*
 * Reads a "single-lined" file. Returns size of the line excluding NUL and
 * excluding \n, guarantees termination on >= 0, truncates silently.
 */
ssize_t
readlineat(int dfd, const char *pathname, char *buf, size_t bufsiz)
{
	int	fd;
	ssize_t n;

	fd = openat(dfd, pathname, O_RDONLY);
	if (fd == -1)
		return (-1);
	n = qread(fd, buf, bufsiz);
	close(fd);
	if (n == -1)
		return (-1);
	else if (n == 0) {
		buf[0] = 0;
		return (0);
	}
	buf[n - 1] = 0;

	return (n - 1);
}

/*
 * Like a strtoull but with proper detection.
 */
int
strtou64(u64 *dst, const char *v, int base)
{
	char	*p;
	u64	 u;

	errno = 0;
	u = strtoull(v, &p, base);
	if (*p != 0 || (u == ULLONG_MAX && errno != 0))
		return (-1);

	*dst = u;

	return (0);
}

char *
find_line(FILE *f, const char *needle)
{
	char		*line, *found;
	size_t		 line_len;
	ssize_t		 n;
	long		 old_pos;

	old_pos = ftell(f);
	if (old_pos == -1)
		return (NULL);
	rewind(f);
	line = NULL;
	line_len = 0;
	found = NULL;
	while ((n = getline(&line, &line_len, f)) != -1) {
		if (line[n - 1] == '\n')
			line[n - 1] = 0;
		if (strncmp(line, needle, strlen(needle)))
			continue;
		found = strdup(line);
		break;
	}
	free(line);
	(void)fseek(f, old_pos, SEEK_SET);

	return (found);
}

char *
find_line_p(const char *path, const char *needle)
{
	FILE	*f;
	char	*line;

	if ((f = fopen(path, "r")) == NULL)
		return (NULL);
	line = find_line(f, needle);
	fclose(f);

	return (line);
}
