// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "quark.h"

const char *words[] = {
	"Tennysonian",
	"hexadactylic",
	"quasi-necessary",
	"kukupa",
	"affirmatory",
	"oyez",
	"multiple-pass",
	"burnettized",
	"headrest",
	"complementation",
	"bookkeeper",
	"Pseudo-european",
	"Nosema",
	"rojak",
	"fortunetelling",
	"OSME",
	"three-pair",
	"unadornable",
	"Perieres",
	"Camelina",
	"yohimbi",
	"ossetic",
	"Yelisavetpol",
	"infixal",
	"spincaster",
	"Bethylidae",
	"Teleoceras",
	"pedialgia",
	"Ettinger",
	"biogenetical",
	"kapellmeister",
	"grantable",
	"gonne",
	"perpetuities",
	"nonentries",
	"contours",
	"unentangle",
	"phthoric",
	"multiserver",
	"sericiculturist",
	"jackeen",
	"Waldman",
	"slich",
	"dimples",
	"lacework",
	"bandicoot",
	"splenopexia",
	"Cassidulina",
	"egressed",
	"malaromas",
	"formulators",
	"penalising",
	"stuffier",
	"pawk",
	"Polad",
	"mastix",
	"gimbri",
	"scarious",
	"procreatress",
	"undeferrable",
	"countercompetition",
	"superload",
	"hypoionian",
	"diphosphate",
	"nonambitiousness",
	"deleading",
	"gasless",
	"marabouts",
	"geomorphic",
	"grand-slammer",
	"knockstone",
	"sister",
	"strangerdom",
	"downlier",
	"wet-plate",
	"consult",
	"palew",
	"Orbitelariae",
	"Grouchy",
	"Lian",
	"draftings",
	"lip-blushing",
	"nonmoderateness",
	"outright",
	"dowery",
	"attendance",
	"Sabia",
	"Hayari",
	"blastophore",
	"overcapitalizes",
	"unsartorially",
	"Sc",
	"homozygote",
	"superornamental",
	"boigid",
	"expostulations",
	"Squamipennes",
	"lyreflower",
	"accuracy",
	"Chicora",
	"Olwena",
	"Exchequer",
	"diatropism",
	"Tizes",
	"quasi-private",
	"physiosophy",
	"acyanopsia",
	"obtruded",
	"unsolubleness",
	"low-born",
	"black-stoled",
	"Neotoma",
	"Ashburnham",
	"hexaplaric",
	"nonprescriber",
	"parisonic",
	"negativate",
	"cyan-",
	"Rhaeto-romanic",
	"consimile",
	"sandy-flaxen",
	"aggravation",
	"antesignanus",
	"nonconversableness",
	"leasemonger",
	"pakpak-lauin",
	"Ciboney",
	"caranx",
	"chemokinesis",
	"brere",
	"roughleg",
	"haunches",
	"Berard",
	"lactucerin",
	"Calderca",
	"metapostscutellum",
	"pind",
	"Perceval",
	"Post-copernican",
	"hypophyllous",
	"Eleazar",
	"ambuscadoed",
	"quick-wittedly",
	"unchaplain",
	"Pleuronectidae",
	"shamoys",
	"amoebula",
	"pass",
	"raunchily",
	"unregained",
	"litteratim",
	"asterion",
	"haunts",
	"Maribor",
	"prussianising",
	"amphibians",
	"outbreathe",
	"interrupter",
	"scabrate",
	"oilstone",
	"semiminim",
	"Eruca",
	"nongravities",
	"Cottageville",
	"alloisomerism",
	"guacin",
	"nonimperious",
	"antrustion",
	"Moresco",
	"Lashond",
	"manorial",
	"allotter",
	"neutralization",
	"rattan",
	"deducer",
	"Bevin",
	"feeblenesses",
	"a-borning",
	"IRD",
	"omentotomy",
	"gweducks",
	"unalienably",
	"sophic",
	"imputrid",
	"ender",
	"Brunonia",
	"outskipped",
	"approximately",
	"misconceives",
	"Silma",
	"rutherfordium",
	"devil-fish",
	"cauldrife",
	"hand-fives",
	"suggestiveness",
	"chinoline",
	"Coors",
	"thermo",
	"Drina",
	"Sorbonne",
};

static int
string_bench(char **buf, size_t *buf_len)
{
	struct hanson	h;
	int		i, first = 1;

	if (hanson_open(&h) == -1)
		return (-1);

	hanson_add_array(&h, "string_bench", NULL);

	for (i = 0; i < (int)nitems(words); i++)
		hanson_add_string(&h, (char *)words[i], &first);

	hanson_close_array(&h);

	if (hanson_close(&h, buf, buf_len) == -1)
		return (-1);

	return (0);
}

static int
int_bench(char **buf, size_t *buf_len)
{
	struct hanson	h;
	int		i, first = 1;

	if (hanson_open(&h) == -1)
		return (-1);

	hanson_add_array(&h, "int_bench", NULL);

	/*
	 * Add zero to 3 digit numbers
	 */
	for (i = 0; i < 300; i++)
		hanson_add_integer(&h, i, &first);
	/*
	 * Add really long numbers, so we can average short + long numbers.
	 * Long numbers are actually cheaper by byte, as in we get better
	 * throughput if we use only long.
	 */
	for (i = 0; i < 300; i++)
		hanson_add_integer(&h, INT64_MAX - (int64_t)i, &first);

	hanson_close_array(&h);

	if (hanson_close(&h, buf, buf_len) == -1)
		return (-1);

	return (0);
}

static int
comb_bench(char **buf, size_t *buf_len)
{
	struct hanson	h;
	int		i, first = 1;

	if (hanson_open(&h) == -1)
		return (-1);

	hanson_add_array(&h, "comb_bench", NULL);

	for (i = 0; i < (int)nitems(words); i++)
		hanson_add_key_value_int(&h, (char *)words[i], i, &first);

	hanson_close_array(&h);

	if (hanson_close(&h, buf, buf_len) == -1)
		return (-1);

	return (0);
}

static void
run_bench(int (*bench)(char **, size_t *), int iterations)
{
	struct timespec	 start, end;
	double		 time_spent, doc_per_s, doc_size, mb_per_s;
	int		 i;
	char		*buf;
	size_t		 buf_len;

	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
		err(1, "clock_gettime");

	for (i = 0; i < iterations; i++) {
		if (bench(&buf, &buf_len) == -1)
			err(1, "failed");
		free(buf);
	}

	if (clock_gettime(CLOCK_MONOTONIC, &end) == -1)
		err(1, "clock_gettime");

	time_spent = (double)(end.tv_sec - start.tv_sec) +
	    (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
	doc_per_s = iterations / time_spent;
	doc_size = (double)buf_len / 1000.0;
	mb_per_s = (((double)buf_len * (double)iterations) / time_spent) /
	    1000.0 / 1000.0;

	printf("Time elapsed: %f seconds\n", time_spent);
	printf("Documents per second: %.2f\n", doc_per_s);
	printf("Document size: %.2fKB\n", doc_size);
	printf("Throughput: %.2fMB/s\n", mb_per_s);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [benchmark]\n", program_invocation_short_name);
	fprintf(stderr, "benchmarks: string* int combined\n");

	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *bench;

	if (argc == 1)
		bench = "string";
	else if (argc == 2)
		bench = argv[1];
	else
		usage();

	if (!strncmp(bench, "comb", 4))
		run_bench(comb_bench, 1000000);
	else if (!strcmp(bench, "string"))
		run_bench(string_bench, 1000000);
	else if (!strcmp(bench, "int"))
		run_bench(int_bench, 100000);
	else
		usage();

	return (0);
}
