# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Elastic NV
#
# Binaries meant for another machine want LDFLAGS=-static.

CFLAGS?=	-g -O2
CPPFLAGS+=	-D_GNU_SOURCE
CDIAGFLAGS=	-Wall -Wextra -Werror -Wmissing-prototypes -Wshadow
CDIAGFLAGS+=	-Wstrict-prototypes -Wno-unused-parameter

# As in ../Makefile
ifeq ($(V),1)
Q=
msg=
QMAKE=
else
Q= @
msg= @printf '  %-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
QMAKE= -s
endif

all: udp-load with-quark

udp-load: udp-load.c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ \
		udp-load.c -lpthread $(LDLIBS)

with-quark:
	$(Q)$(MAKE) $(QMAKE) -C .. with-quark

clean:
	$(call msg,CLEAN,$(notdir $(CURDIR)))
	$(Q)rm -f udp-load

.PHONY: all clean with-quark
