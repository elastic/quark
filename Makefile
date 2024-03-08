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

CC?= cc

# LIBQUARK
LIBQUARK_HEADERS:= $(wildcard *.h)
LIBQUARK_SRCS:= $(filter-out quark-mon.c quark-btf.c,$(wildcard *.c))
LIBQUARK_OBJS:= $(patsubst %.c,%.o,$(LIBQUARK_SRCS))
LIBQUARK_STATIC:= libquark.a
SVGS:= $(patsubst %.dot,%.svg,$(wildcard *.dot))

# Embedded LIBBPF
LDFLAGS+= -lelf -lz
LIBBPF_SRC:= libbpf/src
LIBBPF_STATIC:= $(LIBBPF_SRC)/libbpf.a
LIBBPF_DEPS:= $(wildcard libbpf/src/*.[ch]) $(wildcard libbpf/include/*.[ch])

all: $(LIBBPF_STATIC) $(LIBQUARK_OBJS) $(LIBQUARK_STATIC) quark-mon quark-btf

$(LIBBPF_STATIC): $(LIBBPF_DEPS)
	make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=y

$(LIBQUARK_STATIC): $(LIBQUARK_OBJS)
	ar rcs $@ $^

%.o: %.c $(LIBQUARK_HEADERS)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $<

%.svg: %.dot
	dot -Tsvg $< -o $@

svg: $(SVGS)

quark-mon: quark-mon.c $(LIBQUARK_STATIC) $(LIBBPF_STATIC)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ $^

quark-btf: quark-btf.c $(LIBQUARK_STATIC) $(LIBBPF_STATIC)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(LIBQUARK_OBJS) $(LIBQUARK_STATIC) quark-mon quark-mon.o quark-btf quark-btf.o

cleanall: clean
	rm -f $(SVGS)
	make -C $(LIBBPF_SRC) clean

.PHONY: all clean cleanall
