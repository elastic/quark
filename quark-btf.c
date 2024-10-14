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

static int		bflag;
static int		fflag;
static int		gflag;
static int		lflag;

static void
disply_version(void)
{
	printf("%s-%s\n", program_invocation_short_name, QUARK_VERSION);
	printf("License: Apache-2.0\n");
	printf("Copyright (c) 2024 Elastic NV\n");

	exit(0);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-bv] [targets...]\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s [-bv] [-f btf_file]\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s [-bv] [-l version]\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s [-v] [-g btf_file name version]\n",
	    program_invocation_short_name);
	fprintf(stderr, "usage: %s -V\n", program_invocation_short_name);

	exit(1);
}

static size_t
calc_longest(struct quark_btf *qbtf)
{
	struct quark_btf_target	*ta;
	size_t			 longest;

	for (ta = qbtf->targets, longest = 0; ta->dotname != NULL; ta++)
		if (strlen(ta->dotname) > longest)
			longest = strlen(ta->dotname);

	return (longest);
}

static void
printit(const char *t, ssize_t off, size_t longest)
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

static struct quark_btf_target *
target_lookup(struct quark_btf *qbtf, const char *dotname)
{
	struct quark_btf_target	*ta;

	for (ta = qbtf->targets; ta->dotname != NULL; ta++) {
		if (!strcmp(ta->dotname, dotname))
			return (ta);
	}

	return (NULL);
}

static void
quark_btf_printit(struct quark_btf *qbtf, int argc, char *argv[])
{
	struct quark_btf_target	*ta;
	size_t			 longest;
	int			 i;

	if (argc == 0)
		longest = calc_longest(qbtf);
	else {
		for (i = 0, longest = 0; i < argc; i++)
			if (strlen(argv[i]) > longest)
				longest = strlen(argv[i]);
	}

	/* Print them all */
	if (argc == 0) {
		for (ta = qbtf->targets; ta->dotname != NULL; ta++)
			printit(ta->dotname, ta->offset, longest);

		return;
	}

	/* Print only the requested ones if argc */
	for (i = 0; i < argc; i++) {
		ta = target_lookup(qbtf, argv[i]);
		if (ta == NULL)
			errx(1, "dotname `%s` doesn't exist, "
			    "did you type it correctly?", argv[i]);
		printit(ta->dotname, ta->offset, longest);
	}
}

static int
gen_c(int argc, char *argv[])
{
	char			*p;
	const char		*path, *distro, *version;
	struct quark_btf	*qbtf;
	struct quark_btf_target	*ta;
	char			 namebuf[1024];
	size_t			 longest;

	if (argc != 3)
		usage();

	path = argv[0];
	distro = argv[1];
	version = argv[2];
	/*
	 * First we figure the name of the structure, this is basically an
	 * escaped concat(distro, version)
	 */
	if (snprintf(namebuf, sizeof(namebuf), "%s_%s", distro, version) >=
	    (int)sizeof(namebuf))
		errx(1, "distro + version is too long");
	/*
	 * Escape invalid characters since this will be the name of the
	 * structure
	 */
	for (p = namebuf; *p != 0; p++) {
		if (*p == '.' || *p == '-' || *p == '/')
			*p = '_';
	}

	if ((qbtf = quark_btf_open2(path, version)) == NULL)
		err(1, "quark_btf_open");

	/*
	 * Declare the structure as static to make sure it gets referenced
	 * later in all_btfs[].
	 */
	longest = calc_longest(qbtf);
	printf("static struct quark_btf %s = {\n", namebuf);
	printf("\t\"%s\", {\n", version);
	for (ta = qbtf->targets; /* NADA */; ta++) {
		const char	*dotname;
		size_t		 off;

		printf("\t{ ");
		if (ta->dotname != NULL) {
			off = 1;
			dotname = ta->dotname;
			printf("\"%s\",", ta->dotname);
		} else {
			off = 3;
			dotname = "NULL";
			printf("NULL,");
		}
		printf("%-*s%-5zd },\n",
		    (int)longest - (int)strlen(dotname) + (int)off, " ",
		    ta->offset);

		if (ta->dotname == NULL)
			break;
	}
	printf("\t}\n};\n\n");

	quark_btf_close(qbtf);

	return (0);
}

static int
hub_lookup(int argc, char *argv[])
{
	struct quark_btf	*qbtf;

	if (argc != 1)
		usage();

	qbtf = quark_btf_open_hub(argv[0]);
	if (qbtf == NULL)
		errx(1, "can't match `%s` with any kernel in btfhub", optarg);
	printf("%s\n", qbtf->kname);
	if (quark_verbose)
		quark_btf_printit(qbtf, 0, NULL);
	quark_btf_close(qbtf);

	return (0);
}

static int
doit(const char *path, int argc, char *argv[])
{
	struct quark_btf	*qbtf;

	if (path == NULL)
		qbtf = quark_btf_open();
	else
		qbtf = quark_btf_open2(path, "temp");

	if (qbtf == NULL)
		err(1, "can't open btf, maybe some offsets failed");

	quark_btf_printit(qbtf, argc, argv);
	quark_btf_close(qbtf);

	return (0);
}

int
main(int argc, char *argv[])
{
	int			 ch;
	const char		*path = NULL;

	while ((ch = getopt(argc, argv, "bf:glvV")) != -1) {
		switch (ch) {
		case 'b':
			bflag = 1;
			break;
		case 'g':
			gflag = 1;
			break;
		case 'l':
			lflag = 1;
			break;
		case 'f':
			if (optarg == NULL)
				usage();
			path = optarg;
			fflag = 1;
			break;
		case 'v':
			quark_verbose++;
			break;
		case 'V':
			disply_version();
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if ((fflag + gflag + lflag) > 1)
		usage();

	/* path distro version */
	if (gflag)
		return (gen_c(argc, argv));

	if (lflag)
		return (hub_lookup(argc, argv));

	return (doit(path, argc, argv));
}
