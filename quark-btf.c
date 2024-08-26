// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

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

static size_t		longest;
static int		bflag;

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-bv] [targets...]\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s [-bv] [-f btf_path]\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s [-v] [-f btf_path] [-g btf_name]\n",
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

struct quark_btf sample = {
	"kname_sample",
	{{ "cred.cap_ambient",		-1 },
	 { "cred.cap_bset",		-1 },
	 { "cred.cap_effective",	-1 },
	 { NULL,			-1 }},
};

static void
gen_c(struct quark_btf *qbtf)
{
	const char		*k;
	char			*v, *p;
	struct quark_btf_target	*ta;

	k = qbtf->kname;
	v = strdup(k);
	/* Mangle invalid characters */
	for (p = v; *p != 0; p++) {
		if (*p == '.' || *p == '-' || *p == '/')
			*p = '_';
	}

	/*
	 * Declare the structure as static to make sure it gets referenced
	 * later in all_btfs[].
	 */
	printf("static struct quark_btf %s = {\n", v);
	printf("\t\"%s\", {\n", k);
	for (ta = qbtf->targets; ta->dotname != NULL; ta++) {
		printf("\t{ ");
		printf("\"%s\",", ta->dotname);
		printf("%-*s%-5zd },\n",
		    (int)longest - (int)strlen(ta->dotname) + 1, " ",
		    ta->offset);
	}
	printf("\t}\n};\n\n");

	free(v);
}

int
main(int argc, char *argv[])
{
	int			 i, ch, failed;
	struct btf		*btf;
	struct quark_btf	*qbtf;
	struct quark_btf_target	*ta;
	const char		*path = NULL;
	const char		*g_name = NULL;

	while ((ch = getopt(argc, argv, "bf:g:v")) != -1) {
		switch (ch) {
		case 'b':
			bflag = 1;
			break;
		case 'g':
			if (optarg == NULL)
				usage();
			g_name = optarg;
			break;
		case 'f':
			if (optarg == NULL)
				usage();
			path = optarg;
			break;
		case 'v':
			quark_verbose++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		if ((qbtf = quark_btf_open(path, g_name)) == NULL)
			err(1, "quark_btf_open");
		for (ta = qbtf->targets, longest = 0; ta->dotname != NULL; ta++)
			if (strlen(ta->dotname) > longest)
				longest = strlen(ta->dotname);
		if (g_name != NULL)
			gen_c(qbtf);
		else {
			for (ta = qbtf->targets; ta->dotname != NULL; ta++)
				printit(ta->dotname, ta->offset);
		}
		quark_btf_close(qbtf);

		return (0);
	}

	btf = btf__load_vmlinux_btf();
	if (IS_ERR_OR_NULL(btf))
		err(1, "btf__load_vmlinux_btf");

	for (i = 0; i < argc; i++)
		if (strlen(argv[i]) > longest)
			longest = strlen(argv[i]);
	for (i = 0, failed = 0; i < argc; i++) {
		s32	off;

		off = btf_root_offset(btf, argv[i]);
		if (off == -1)
			failed = 1;
		printit(argv[i], off);
	}

	btf__free(btf);

	return (failed);
}
