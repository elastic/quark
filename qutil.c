#include <ctype.h>		/* is_digit(3) */
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

char *
load_file_nostat(int fd, size_t *total)
{
	ssize_t		n, bufsize, copied;
	char		*buf, *nbuf;

	buf = NULL;
	bufsize = 0;
	copied = 0;
	for (; ;) {
		if (bufsize - copied == 0) {
			bufsize = bufsize == 0 ? 4096 : bufsize * 2;
			/* Grow with one extra for NUL */
			nbuf = realloc(buf, bufsize + 1);
			if (nbuf == NULL) {
				free(buf);
				return (NULL);
			}
			buf = nbuf;
		}
		n = qread(fd, buf + copied, bufsize - copied);
		if (n == -1) {
			free(buf);
			return (NULL);
		} else if (n == 0) {
			/* We allocate an extra byte to guarantee NUL space */
			buf[copied] = 0;
			break;
		}
		copied += n;
	}

	/* Signal an empty file with NULL */
	if (copied == 0) {
		free(buf);
		buf = NULL;
	}
	if (total != NULL)
		*total = copied;

	return (buf);
}

/* buf_len includes the terminating NUL */
struct args *
args_make(struct quark_event *qev)
{
	struct args	*args;
	const char	*p, *end;
	int		 i, argc;
	const char 	*buf;
	size_t		 buf_len;

	buf = qev->cmdline;
	buf_len = qev->cmdline_len;

	if (buf_len == 0 || buf[buf_len - 1] != 0)
		return (NULL);
	/* Walk source and count how many arguments */
	argc = 0;
	end = buf + buf_len;
	for (p = buf; p < end; p += strlen(p) + 1)
		argc++;

	/*
	 * Allocate with variadic end
	 */
	if ((args = calloc(1, sizeof(*args) + (argc * sizeof(char *)))) == NULL)
		goto fail;
	if ((args->buf = malloc(buf_len)) == NULL)
		goto fail;
	memcpy(args->buf, buf, buf_len);
	args->buf_len = buf_len;

	/*
	 * This is a bit paranoic, we recheck what we already know.
	 */
	i = 0;
	end = args->buf + args->buf_len;
	for (p = args->buf;
	     p < end && i < argc && *p != 0;
	     p += strlen(p) + 1) {
		args->argv[i++] = p;
	}
	args->argc = i;

	return (args);

fail:
	if (args != NULL)
		free(args->buf);
	free(args);

	return (NULL);
}

void
args_free(struct args *args) {
	free(args->buf);
	free(args);
}
