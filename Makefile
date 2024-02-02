CFLAGS?= -g -O2 -fno-strict-aliasing

CPPFLAGS?=-D_GNU_SOURCE

CDIAGFLAGS+= -Wall
CDIAGFLAGS+= -Wextra
CDIAGFLAGS+= -Werror
CDIAGFLAGS+= -Wchar-subscripts
CDIAGFLAGS+= -Wcomment
CDIAGFLAGS+= -Wformat
CDIAGFLAGS+= -Wformat-security
CDIAGFLAGS+= -Wimplicit
CDIAGFLAGS+= -Winline
CDIAGFLAGS+= -Wmissing-declarations
CDIAGFLAGS+= -Wmissing-prototypes
CDIAGFLAGS+= -Wparentheses
CDIAGFLAGS+= -Wpointer-arith
CDIAGFLAGS+= -Wreturn-type
CDIAGFLAGS+= -Wshadow
CDIAGFLAGS+= -Wsign-compare
CDIAGFLAGS+= -Wstrict-prototypes
CDIAGFLAGS+= -Wswitch
CDIAGFLAGS+= -Wtrigraphs
CDIAGFLAGS+= -Wuninitialized
CDIAGFLAGS+= -Wunused
CDIAGFLAGS+= -Wno-unused-parameter

LDFLAGS?= -lbsd

CC?= cc
HEADERS:= $(wildcard *.h)
SRCS:= $(wildcard *.c)
PROGS:= $(patsubst %.c,%,$(SRCS))
SVGS:= $(patsubst %.dot,%.svg,$(wildcard *.dot))

%: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ $<

all: $(PROGS)

%.svg: %.dot
	dot -Tsvg $< -o $@

svg: $(SVGS)

clean:
	rm -f $(PROGS)

cleanall: clean
	rm -f $(SVGS)

.PHONY: all clean cleanall
