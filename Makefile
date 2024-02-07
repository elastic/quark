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

# LIBBPF wants these
LDFLAGS?=-lelf -lz

CC?= cc
HEADERS:= $(wildcard *.h)
SRCS:= $(wildcard *.c)
PROGS:= quark
OBJS:= $(patsubst %.c,%.o,$(SRCS))
SVGS:= $(patsubst %.dot,%.svg,$(wildcard *.dot))

LIBBPF_SRC:= libbpf/src
LIBBPF_STATIC:= $(LIBBPF_SRC)/libbpf.a
LIBBPF_DEPS:= $(wildcard libbpf/src/*.[ch]) $(wildcard libbpf/include/*.[ch])

%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $<

$(PROGS): $(OBJS) $(LIBBPF_STATIC)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ $^

$(LIBBPF_STATIC):
	make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=y

all: $(PROGS)

%.svg: %.dot
	dot -Tsvg $< -o $@

svg: $(SVGS)

clean:
	rm -f $(OBJS) $(PROGS)

cleanall: clean
	rm -f $(SVGS)
	make -C $(LIBBPF_SRC) clean

.PHONY: all clean cleanall
