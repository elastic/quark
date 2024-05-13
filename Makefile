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
CLANG?= clang
BPFTOOL?= bpftool

# All EEBPF files we track for dependency
EEBPF_FILES:= $(shell find ./elastic-ebpf)
EEBPF_INCLUDES:= -Ielastic-ebpf/GPL/Events -Ielastic-ebpf/contrib/vmlinux/x86_64

# LIBQUARK
LIBQUARK_DEPS:= $(wildcard *.h) bpf_prog_skel.h $(EEBPF_FILES)
LIBQUARK_SRCS:= $(filter-out bpf_prog.c quark-mon.c quark-btf.c,$(wildcard *.c))
LIBQUARK_OBJS:= $(patsubst %.c,%.o,$(LIBQUARK_SRCS))
LIBQUARK_STATIC:= libquark.a
SVGS:= $(patsubst %.dot,%.svg,$(wildcard *.dot))

# Embedded LIBBPF
LDFLAGS+= -lelf -lz
LIBBPF_SRC:= libbpf/src
LIBBPF_STATIC:= $(LIBBPF_SRC)/libbpf.a
LIBBPF_DEPS:= $(wildcard libbpf/src/*.[ch]) $(wildcard libbpf/include/*.[ch])

# BPFPROG (kernel side)
BPFPROG_OBJ:= bpf_prog.o
BPFPROG_DEPS:= bpf_prog.c $(LIBBPF_DEPS) $(EEBPF_FILES)

all: $(LIBBPF_STATIC) $(BPFPROG_OBJ) $(LIBQUARK_OBJS) $(LIBQUARK_STATIC) quark-mon quark-btf README.md

$(LIBBPF_STATIC): $(LIBBPF_DEPS)
	$(call msg,MAKE,$@)
	$(Q)make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=y EXTRA_CFLAGS=-fPIC

$(LIBQUARK_STATIC): $(LIBQUARK_OBJS)
	$(call msg,AR,$@)
	$(Q)ar rcs $@ $^

$(BPFPROG_OBJ): $(BPFPROG_DEPS)
	$(call msg,CLANG,bpf_prog.tmp.o)
	$(Q)$(CLANG) -g -O2 -target bpf -D__KERNEL__ -D__TARGET_ARCH_x86 \
		-Ilibbpf/include/uapi -Ilibbpf/src $(EEBPF_INCLUDES) \
		-c bpf_prog.c -o bpf_prog.tmp.o
	$(call msg,BPFTOOL,$@)
	$(Q)$(BPFTOOL) gen object $@ bpf_prog.tmp.o
	$(Q)rm bpf_prog.tmp.o
	$(call msg,BPFTOOL,bpf_prog_skel.h)
	$(Q)$(BPFTOOL) gen skeleton $(BPFPROG_OBJ) > bpf_prog_skel.h
	$(call msg,SED,bpf_prog_skel.h)
	$(Q)sed -i 's/<bpf\/libbpf.h>/\"libbpf\/src\/libbpf.h\"/' bpf_prog_skel.h

%.o: %.c $(LIBQUARK_DEPS)
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

README.md: quark.7
	$(call msg,MANDOC,$@)
	$(Q)mandoc -T markdown -I os=$(shell uname -s) $< > $@
	$(Q)sed -i '$$ d' $@ # Chomp last line

eebpf-sync:
	$(Q)test $(EEBPF_PATH) || \
		(echo "usage: make eebpf-sync EEBPF_PATH=/elastic-ebpf-path"; exit 1)
	$(call msg,SHELL,./elastic-ebpf/sync.sh $(EEBPF_PATH))
	$(Q)./elastic-ebpf/sync.sh $(EEBPF_PATH)

clean:
	$(call msg,CLEAN)
	$(Q)rm -f *.o *.a quark-mon quark-btf bpf_prog_skel.h

cleanall: clean
	$(call msg,CLEANALL)
	$(Q)rm -f $(SVGS)
	$(Q)make -C $(LIBBPF_SRC) clean

manlint:
	$(call msg, MANDOC)
	$(Q)mandoc -Tlint *.[378] || true

.PHONY: all clean cleanall manlint eebpf-sync
