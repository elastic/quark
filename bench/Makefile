# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Elastic NV
#
# with-quark, the harness the benchmarks share, then each benchmark.
# Binaries meant for another machine want LDFLAGS=-static.

QUARK?=		..
LIBQUARK?=	$(QUARK)/libquark_big.a
SUBDIR=		flows

CFLAGS?=	-g -O2
CPPFLAGS+=	-D_GNU_SOURCE -I$(QUARK) -I$(QUARK)/include
CDIAGFLAGS=	-Wall -Wextra -Werror -Wmissing-prototypes -Wshadow
CDIAGFLAGS+=	-Wstrict-prototypes -Wno-unused-parameter

all: with-quark $(SUBDIR)

with-quark: with-quark.c $(LIBQUARK)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ \
		with-quark.c $(LIBQUARK) $(LDLIBS)

# Always check if the library is out of date via the top level Makefile,
# as a stale library would have us measure old code.
$(LIBQUARK): FORCE
	$(MAKE) -C $(QUARK) $(notdir $(LIBQUARK))

FORCE:

$(SUBDIR): with-quark
	$(MAKE) -C $@

clean:
	rm -f with-quark
	for d in $(SUBDIR); do $(MAKE) -C $$d clean; done

.PHONY: all clean FORCE $(SUBDIR)
