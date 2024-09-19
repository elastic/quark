SHELL= /bin/bash
PWD= $(shell pwd)

# Normalize ARCH
ifeq ($(shell uname -m), x86_64)
	ARCH?= amd64
else ifeq ($(shell uname -m), aarch64)
	ARCH?= arm64
endif
ifeq ($(ARCH), amd64)
	ARCH_ALT?= x86_64
	ARCH_BPF_TARGET?= x86
else ifeq ($(ARCH), arm64)
	ARCH_ALT?= aarch64
	ARCH_BPF_TARGET?= arm64
else
$(error unsupported architecture $(ARCH))
endif

ifeq ($(V),1)
	Q =
	msg =
	QDOCKER =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
	QREDIR = > /dev/null
	QDOCKER = -q
endif

CFLAGS?= -g -O2 -fno-strict-aliasing -fPIC

CPPFLAGS?= -D_GNU_SOURCE -Iinclude/usr/include

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

CLANG?= clang
BPFTOOL?= bpftool
DOCKER?= docker

# All EEBPF files we track for dependency
EEBPF_FILES:= $(shell find elastic-ebpf)
EEBPF_INCLUDES:= -Ielastic-ebpf/GPL/Events -Ielastic-ebpf/contrib/vmlinux/$(ARCH_ALT)

# LIBQUARK
LIBQUARK_DEPS:= $(wildcard *.h) bpf_prog_skel.h $(EEBPF_FILES) include
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
LIBBPF_DEPS:=	$(wildcard libbpf/src/*.[ch])		\
		$(wildcard libbpf/include/*.[ch])	\
		$(ELFTOOLCHAIN_FILES)
LIBBPF_EXTRA_CFLAGS:= -DQUARK
LIBBPF_EXTRA_CFLAGS+= -fPIC
LIBBPF_EXTRA_CFLAGS+= -I../../elftoolchain/libelf
LIBBPF_EXTRA_CFLAGS+= -I../../elftoolchain/common
LIBBPF_EXTRA_CFLAGS+= -I../../zlib

# BPFPROG (kernel side)
BPFPROG_OBJ:= bpf_prog.o
BPFPROG_DEPS:= bpf_prog.c $(LIBBPF_DEPS) $(EEBPF_FILES) include

# DOCS_HTML, matches docs/%.html
DOCS:= $(wildcard *.[378])
DOCS_HTML:= $(patsubst %.3,docs/%.3.html,$(wildcard *.3))
DOCS_HTML+= $(patsubst %.7,docs/%.7.html,$(wildcard *.7))
DOCS_HTML+= $(patsubst %.8,docs/%.8.html,$(wildcard *.8))

all:	$(ZLIB_STATIC)			\
	$(ELFTOOLCHAIN_STATIC)		\
	$(LIBBPF_STATIC)		\
	$(BPFPROG_OBJ)			\
	$(LIBQUARK_STATIC)		\
	$(LIBQUARK_STATIC_BIG)		\
	quark-mon			\
	quark-btf

$(ZLIB_STATIC): $(ZLIB_FILES)
	@cd zlib && CFLAGS="-O3 -fPIC" ./configure --static $(QREDIR)
	@make -C zlib libz.a

$(ELFTOOLCHAIN_STATIC): $(ELFTOOLCHAIN_FILES)
	$(Q)make -C elftoolchain/libelf

$(LIBBPF_STATIC): $(LIBBPF_DEPS)
	$(Q)make -C $(LIBBPF_SRC)		\
			BUILD_STATIC_ONLY=y	\
			NO_PKG_CONFIG=y		\
			EXTRA_CFLAGS="$(LIBBPF_EXTRA_CFLAGS)"

$(LIBQUARK_STATIC): $(LIBQUARK_OBJS)
	$(call msg,AR,$@)
	$(Q)$(AR) rcs $@ $^

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

$(BPFPROG_OBJ): $(BPFPROG_DEPS)
	$(call msg,CLANG,bpf_prog.tmp.o)
	$(Q)$(CLANG)								\
		-g -O2								\
		-target bpf							\
		-D__KERNEL__							\
		-D__TARGET_ARCH_$(ARCH_BPF_TARGET)				\
		$(CPPFLAGS)							\
		$(EEBPF_INCLUDES)						\
		-c bpf_prog.c							\
		-o bpf_prog.tmp.o
	$(call msg,BPFTOOL,$@)
	$(Q)$(BPFTOOL) gen object $@ bpf_prog.tmp.o
	$(Q)rm bpf_prog.tmp.o

DOCKER_RUN_ARGS=$(QDOCKER)				\
		-v $(PWD):$(PWD)			\
		-w $(PWD)				\
		-u $(shell id -u):$(shell id -g)	\
		quark-builder

docker: docker-image clean-all
	$(call msg,DOCKER-RUN,Dockerfile)
	$(Q)$(DOCKER) run $(DOCKER_RUN_ARGS) /bin/bash -c make -C $(PWD)

docker-cross-arm64: docker-image clean-all
	$(call msg,DOCKER-RUN,Dockerfile)
	$(Q)$(DOCKER) run				\
		-e ARCH=arm64				\
		-e CC=aarch64-linux-gnu-gcc		\
		-e LD=aarch64-linux-gnu-ld		\
		-e AR=aarch64-linux-gnu-ar		\
		$(DOCKER_RUN_ARGS)			\
		/bin/bash -c make -C $(PWD)

docker-image: clean-all
	$(call msg,DOCKER-IMAGE,Dockerfile)
	$(Q)$(DOCKER) build				\
		$(QDOCKER)				\
		-f Dockerfile				\
		-t quark-builder			\
		.

docker-shell:
	$(DOCKER) run -it $(DOCKER_RUN_ARGS) /bin/bash

include: $(LIBBPF_DEPS)
	$(Q)make -C $(LIBBPF_SRC)			\
		NO_PKG_CONFIG=y				\
		install_headers DESTDIR=../../include $(QREDIR)
	$(Q)make -C $(LIBBPF_SRC)			\
		NO_PKG_CONFIG=y				\
		install_uapi_headers DESTDIR=../../include $(QREDIR)

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

docs/index.html: docs/quark.7.html
	$(call msg,CP,index.html)
	$(Q)cp $< $@

docs/%.html: %
	$(call msg,MANDOC,$<)
	$(Q)mandoc -Tlint $< || exit 1
	$(Q)mandoc -Thtml -I os=$(shell uname -s) 		\
		-Otoc,style=mandoc.css,man=%N.%S.html $< > $@
	$(Q)sed -i 's/fork\.2\.html/https:\/\/linux.die.net\/man\/2\/fork/g' $@
	$(Q)sed -i 's/exec\.3\.html/https:\/\/linux.die.net\/man\/3\/exec/g' $@
	$(Q)sed -i 's/exit\.3\.html/https:\/\/linux.die.net\/man\/3\/exit/g' $@

docs: $(DOCS_HTML) README.md docs/index.html

btfhub:
	$(Q)test $(BTFHUB_ARCHIVE_PATH) || \
		(echo "usage: make btfhub.c BTFHUB_ARCHIVE_PATH=/btfhub-archive-path"; exit 1)
	$(call msg,SHELL,./genbtf.sh $(BTFHUB_ARCHIVE_PATH))
	$(Q)./genbtf.sh $(BTFHUB_ARCHIVE_PATH) > btfhub.new
	$(call msg,MV,btfhub.c)
	$(Q)mv btfhub.new btfhub.c

eebpf-sync:
	$(Q)test $(EEBPF_PATH) || \
		(echo "usage: make eebpf-sync EEBPF_PATH=/elastic-ebpf-path"; exit 1)
	$(call msg,SHELL,./elastic-ebpf/sync.sh $(EEBPF_PATH))
	$(Q)./elastic-ebpf/sync.sh $(EEBPF_PATH)

clean:
	$(call msg,CLEAN)
	$(Q)rm -f *.o *.a quark-mon quark-btf bpf_prog_skel.h

clean-all: clean
	$(call msg,CLEAN-ALL)
	$(Q)rm -rf docs/*.html
	$(Q)rm -f $(SVGS)
	$(Q)rm -rf include
	$(Q)make -C $(LIBBPF_SRC) clean
	$(Q)make -C $(ELFTOOLCHAIN_SRC)/libelf clean
	$(Q)make -C $(ZLIB_SRC) clean || true

clean-docs:
	$(call msg,CLEAN,docs)
	$(Q)rm -f docs/*.html

.PHONY:				\
	all			\
	btfhub			\
	clean			\
	clean-all		\
	clean-docs		\
	docs			\
	eebpf-sync		\
	docker			\
	docker-cross-arm64	\
	docker-image		\
	docker-shell
.SUFFIXES:
