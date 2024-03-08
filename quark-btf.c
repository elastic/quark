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

extern struct target targets[];

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-b] [targets...]\n",
	    program_invocation_short_name);

	exit(1);
}

int
main(int argc, char *argv[])
{
	int		 i, ch, bflag;
	struct btf	*btf;
	struct target	*ta;
	size_t		 longest;
	char		 fmt[1024];

	bflag = 0;
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

	if (argc == 0) {
		if (quark_btf_init() != 0)
			err(1, "quark_btf_init");
		for (ta = targets, longest = 0; ta->dotname != NULL; ta++)
			if (strlen(ta->dotname) > longest)
				longest = strlen(ta->dotname);
		if (snprintf(fmt, sizeof(fmt),
		    "%%-%zds %%-7zd", longest) >= (int)sizeof(fmt))
			errx(1, "fmt too long");
		for (ta = targets; ta->dotname != NULL; ta++) {
			printf(fmt, ta->dotname, ta->offset);
			if (bflag && ta->offset != -1)
				printf("%zd", ta->offset * 8);
			printf("\n");
			fflush(stdout);
		}
		return (0);
	}

	btf = btf__load_vmlinux_btf();
	if (IS_ERR_OR_NULL(btf))
		err(1, "btf__load_vmlinux_btf");

	for (i = 0; i < argc; i++)
		if (strlen(argv[i]) > longest)
			longest = strlen(argv[i]);
	if (snprintf(fmt, sizeof(fmt),
	    "%%-%zds %%-7zd", longest) >= (int)sizeof(fmt))
		errx(1, "fmt too long");
	for (i = 0; i < argc; i++) {
		s32	off;

		off = btf_root_offset(btf, argv[i]);
		printf(fmt, argv[i], off);
		if (bflag && off != -1)
			printf("%d", off * 8);
		printf("\n");
		fflush(stdout);
	}

	btf__free(btf);

	return (0);
}
