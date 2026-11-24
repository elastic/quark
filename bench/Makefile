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

# The top level Makefile hands us the libraries quark needs in LDLIBS. If the
# build starts here this doesn't take place, and on musl quark needs one extra
# library. MUSL is found in the same way as the top level.
ifeq ($(shell ldd --version 2>&1|head -n1|grep -q ^musl && echo yes), yes)
MUSL?= 1
endif
ifdef MUSL
LDLIBS?= -lfts
endif

# We log the way the top level Makefile does: a line for each thing made,
# or every command in full with V=1. The makes we start do the same.
ifeq ($(V),1)
Q=
msg=
QMAKE=
else
Q= @
msg= @printf '  %-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
QMAKE= -s
endif

all: with-quark $(SUBDIR)

with-quark: with-quark.c $(LIBQUARK)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ \
		with-quark.c $(LIBQUARK) $(LDLIBS)

# Always check if the library is out of date via the top level Makefile,
# as a stale library would have us measure old code.
$(LIBQUARK): FORCE
	$(Q)$(MAKE) $(QMAKE) -C $(QUARK) $(notdir $(LIBQUARK))

FORCE:

$(SUBDIR): with-quark
	$(call msg,MAKE,$@)
	$(Q)$(MAKE) $(QMAKE) -C $@

clean:
	$(call msg,CLEAN,$(notdir $(CURDIR)))
	$(Q)rm -f with-quark
	$(Q)for d in $(SUBDIR); do $(MAKE) $(QMAKE) -C $$d clean; done

.PHONY: all clean FORCE $(SUBDIR)
