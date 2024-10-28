// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static void
usage(void)
{
	fprintf(stderr, "usage: %s input_file ifdef_name\n",
	    program_invocation_short_name);

	exit(1);
}

static int
embed(const char *input_path, const char *ifdef_name)
{
	FILE	*input;
	int	 ch, line_wrap;

	if ((input = fopen(input_path, "r")) == NULL)
		err(1, "fopen");

	if (ifdef_name != NULL)
		printf("#ifdef %s\n", ifdef_name);
	printf("const char manpage_bin[] = {\n");

	line_wrap = 0;
	while ((ch = fgetc(input)) != EOF) {
		if (line_wrap == 0)
			putchar('\t');
		printf("0x%02x, ", ch);
		if (++line_wrap == 10) {
			putchar('\n');
			line_wrap = 0;
		}
	}
	if (ferror(input))
		errx(1, "input error");
	fclose(input);

	printf("\n};\n");
	if (ifdef_name != NULL)
		printf("#endif /* %s */", ifdef_name);
	putchar('\n');

	return (0);
}

int
main(int argc, char *argv[])
{
	if (argc != 3)
		usage();

	return (embed(argv[1], argv[2]));
}
