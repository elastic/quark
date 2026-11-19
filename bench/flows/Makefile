# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Elastic NV
#
# Binaries meant for another machine want LDFLAGS=-static.

CFLAGS?=	-g -O2
CPPFLAGS+=	-D_GNU_SOURCE
CDIAGFLAGS=	-Wall -Wextra -Werror -Wmissing-prototypes -Wshadow
CDIAGFLAGS+=	-Wstrict-prototypes -Wno-unused-parameter

all: udp-load with-quark

udp-load: udp-load.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ \
		udp-load.c -lpthread $(LDLIBS)

with-quark:
	$(MAKE) -C .. with-quark

clean:
	rm -f udp-load

.PHONY: all clean with-quark
