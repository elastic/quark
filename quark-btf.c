#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "quark.h"

#include "libbpf/src/btf.h"
#include "libbpf/include/linux/err.h"		/* IS_ERR :( */

s32	btf_root_offset(struct btf *, const char *);

struct target {
	const char	*dotname;
	ssize_t		 offset;
};

extern struct target	targets[];
static size_t		longest;
static int		bflag;

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-b] [targets...]\n",
	    program_invocation_short_name);

	exit(1);
}

static void
printit(const char *t, ssize_t off)
{
	printf("%-*s ", (int)longest, t);
	if (off == -1)
		printf("U");
	else
		printf("%-7zd", off);
	if (bflag && off != -1)
		printf("%zd", off * 8);
	printf("\n");
	fflush(stdout);
}

int
main(int argc, char *argv[])
{
	int		 i, ch, failed;
	struct btf	*btf;
	struct target	*ta;

	while ((ch = getopt(argc, argv, "b")) != -1) {
		switch (ch) {
		case 'b':
			bflag = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	longest = 0;
	failed = 0;

	if (argc == 0) {
		if (quark_btf_init() != 0)
			err(1, "quark_btf_init");
		for (ta = targets, longest = 0; ta->dotname != NULL; ta++)
			if (strlen(ta->dotname) > longest)
				longest = strlen(ta->dotname);
		for (ta = targets; ta->dotname != NULL; ta++) {
			if (ta->offset == -1)
				failed = 1;
			printit(ta->dotname, ta->offset);
		}

		return (failed);
	}

	btf = btf__load_vmlinux_btf();
	if (IS_ERR_OR_NULL(btf))
		err(1, "btf__load_vmlinux_btf");

	for (i = 0; i < argc; i++)
		if (strlen(argv[i]) > longest)
			longest = strlen(argv[i]);
	for (i = 0; i < argc; i++) {
		s32	off;

		off = btf_root_offset(btf, argv[i]);
		if (off == -1)
			failed = 1;
		printit(argv[i], off);
	}

	btf__free(btf);

	return (failed);
}
