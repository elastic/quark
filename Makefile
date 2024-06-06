ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
	QREDIR = > /dev/null
endif

CFLAGS?= -g -O2 -fno-strict-aliasing -fPIC

CPPFLAGS?= -D_GNU_SOURCE -Ilibbpf/src

CDIAGFLAGS+= -Wall
CDIAGFLAGS+= -Wextra
CDIAGFLAGS+= -Werror
CDIAGFLAGS+= -Wchar-subscripts
CDIAGFLAGS+= -Wcomment
CDIAGFLAGS+= -Wformat
CDIAGFLAGS+= -Wformat-security
CDIAGFLAGS+= -Wimplicit
CDIAGFLAGS+= -Wimplicit-fallthrough
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
EEBPF_FILES:= $(shell find elastic-ebpf)
EEBPF_INCLUDES:= -Ielastic-ebpf/GPL/Events -Ielastic-ebpf/contrib/vmlinux/x86_64

# LIBQUARK
LIBQUARK_DEPS:= $(wildcard *.h) bpf_prog_skel.h $(EEBPF_FILES)
LIBQUARK_SRCS:= $(filter-out bpf_prog.c quark-mon.c quark-btf.c,$(wildcard *.c))
LIBQUARK_OBJS:= $(patsubst %.c,%.o,$(LIBQUARK_SRCS))
LIBQUARK_STATIC:= libquark.a
LIBQUARK_STATIC_BIG:= libquark_big.a
SVGS:= $(patsubst %.dot,%.svg,$(wildcard *.dot))

# ZLIB
ZLIB_SRC:= zlib
ZLIB_FILES:= $(shell find $(ZLIB_SRC) \(\
	-name '*.[ch]' -o \
	-name Makefile -o \
	-name configure \
\))
ZLIB_STATIC:= $(ZLIB_SRC)/libz.a

# BSD elftoolchain
ELFTOOLCHAIN_SRC:= elftoolchain
ELFTOOLCHAIN_FILES:= $(shell find elftoolchain/{common,libelf} -name '*.[ch]')
ELFTOOLCHAIN_FILES:= $(filter-out elftoolchain/libelftc/elftc_version.c, $(ELFTOOLCHAIN_FILES))
ELFTOOLCHAIN_STATIC:= $(ELFTOOLCHAIN_SRC)/libelf/libelf_pic.a

# Embedded LIBBPF
LIBBPF_SRC:= libbpf/src
LIBBPF_STATIC:= $(LIBBPF_SRC)/libbpf.a
LIBBPF_DEPS:=	$(wildcard libbpf/src/*.[ch]) 		\
		$(wildcard libbpf/include/*.[ch])	\
		$(ELFTOOLCHAIN_FILES)

# BPFPROG (kernel side)
BPFPROG_OBJ:= bpf_prog.o
BPFPROG_DEPS:= bpf_prog.c $(LIBBPF_DEPS) $(EEBPF_FILES)

all:	$(ZLIB_STATIC)			\
	$(ELFTOOLCHAIN_STATIC)		\
	$(LIBBPF_STATIC)		\
	$(BPFPROG_OBJ)			\
	$(LIBQUARK_STATIC)		\
	$(LIBQUARK_STATIC_BIG)		\
	quark-mon			\
	quark-btf			\
	README.md

$(ZLIB_STATIC): $(ZLIB_FILES)
	@cd zlib && ./configure --static $(QREDIR)
	@make -C zlib libz.a

$(ELFTOOLCHAIN_STATIC): $(ELFTOOLCHAIN_FILES)
	$(Q)make -C elftoolchain/libelf

$(LIBBPF_STATIC): $(LIBBPF_DEPS)
	$(Q)make -C $(LIBBPF_SRC)				\
		BUILD_STATIC_ONLY=y				\
		EXTRA_CFLAGS="-DQUARK -fPIC -I../../elftoolchain/libelf -I../../elftoolchain/common"

$(LIBQUARK_STATIC): $(LIBQUARK_OBJS)
	$(call msg,AR,$@)
	$(Q)ar rcs $@ $^

$(LIBQUARK_STATIC_BIG): $(LIBQUARK_STATIC) $(LIBBPF_STATIC) $(ELFTOOLCHAIN_STATIC) $(ZLIB_STATIC)
	$(call msg,AR,$@)
	$(Q)printf "\
	create libquark_big.a\n\
	addlib libquark.a\n\
	addlib libbpf/src/libbpf.a\n\
	addlib elftoolchain/libelf/libelf_pic.a\n\
	addlib zlib/libz.a\n\
	save\n\
	end\n" | ar -M


$(LIBQUARK_OBJS): %.o: %.c $(LIBQUARK_DEPS)
	$(call msg,CC,$@)
	$(Q)$(CC) -c $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) $<

bpf_prog_skel.h: $(BPFPROG_OBJ)
	$(call msg,BPFTOOL,bpf_prog_skel.h)
	$(Q)$(BPFTOOL) gen skeleton $(BPFPROG_OBJ) > bpf_prog_skel.h
	$(call msg,SED,bpf_prog_skel.h)
	$(Q)sed -i 's/<bpf\/libbpf.h>/\"libbpf.h\"/' bpf_prog_skel.h

$(BPFPROG_OBJ): $(BPFPROG_DEPS)
	$(call msg,CLANG,bpf_prog.tmp.o)
	$(Q)$(CLANG) -g -O2 -target bpf -D__KERNEL__ -D__TARGET_ARCH_x86	\
		-Ilibbpf/include/uapi						\
		-Ilibbpf/src $(EEBPF_INCLUDES)					\
		-c bpf_prog.c -o bpf_prog.tmp.o
	$(call msg,BPFTOOL,$@)
	$(Q)$(BPFTOOL) gen object $@ bpf_prog.tmp.o
	$(Q)rm bpf_prog.tmp.o

%.svg: %.dot
	$(call msg,DOT,$@)
	$(Q)dot -Tsvg $< -o $@

svg: $(SVGS)

quark-mon: quark-mon.c $(LIBQUARK_STATIC_BIG)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) -o $@ $^

quark-btf: quark-btf.c $(LIBQUARK_STATIC_BIG)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) -o $@ $^

README.md: quark.7
	$(call msg,MANDOC,$@)
	$(Q)mandoc -T markdown -I os=$(shell uname -s) $< > $@
	$(Q)sed -i '$$ d' $@ # Chomp last line

doc: manlint manhtml README.md

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
	$(Q)rm -rf manhtml/*.html
	$(Q)rm -f $(SVGS)
	$(Q)make -C $(LIBBPF_SRC) clean
	$(Q)make -C $(ELFTOOLCHAIN_SRC)/libelf clean
	$(Q)make -C $(ZLIB_SRC) clean || true

manhtml:
	$(call msg,MKDIR)
	$(Q)mkdir -p manhtml
	$(call msg,MANDOC)
	$(Q)for x in *.[378]; do \
		mandoc -Thtml -Ostyle=mandoc.css,man=%N.%S.html $$x > manhtml/$$x.html; \
	done

manlint:
	$(call msg,MANDOC)
	$(Q)mandoc -Tlint *.[378] || true

.PHONY: all doc eebpf-sync clean cleanall manhtml manlint

.SUFFIXES:
