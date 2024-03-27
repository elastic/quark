ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
endif

CFLAGS?= -g -O2 -fno-strict-aliasing -fPIC

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
	$(call msg,MAKE,$@)
	$(Q)make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=y EXTRA_CFLAGS=-fPIC

$(LIBQUARK_STATIC): $(LIBQUARK_OBJS)
	$(call msg,AR,$@)
	$(Q)ar rcs $@ $^

%.o: %.c $(LIBQUARK_HEADERS)
	$(call msg,CC,$@)
	$(Q)$(CC) -c $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $<

%.svg: %.dot
	$(call msg,DOT,$@)
	$(Q)dot -Tsvg $< -o $@

svg: $(SVGS)

quark-mon: quark-mon.c $(LIBQUARK_STATIC) $(LIBBPF_STATIC)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ $^

quark-btf: quark-btf.c $(LIBQUARK_STATIC) $(LIBBPF_STATIC)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $(LDFLAGS) -o $@ $^

clean:
	$(call msg,CLEAN)
	$(Q)rm -f $(LIBQUARK_OBJS) $(LIBQUARK_STATIC) \
		quark-mon quark-mon.o quark-btf quark-btf.o

cleanall: clean
	$(call msg,CLEANALL)
	$(Q)rm -f $(SVGS)
	$(Q)make -C $(LIBBPF_SRC) clean

.PHONY: all clean cleanall
