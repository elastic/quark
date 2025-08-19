SHELL= /bin/bash
PWD= $(shell pwd)
HTML2MARKDOWN?= html2markdown
SUDO?= sudo
GO?= go

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

# Check if we are in a musl system
ifeq ($(shell ldd --version 2>&1|head -n1|grep -q ^musl && echo yes), yes)
	MUSL?=1
endif

# Musl doesn't have fts, but distributions provide a libfts
ifdef MUSL
EXTRA_LDFLAGS+= -lfts
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

define assert_no_syslib
  $(if $(SYSLIB), $(error cant build target $@ with SYSLIB))
endef

CFLAGS?= -g -O2 -fno-strict-aliasing -fPIC
ifdef CENTOS7
CFLAGS+= -std=gnu99 -DNO_PUSH_PRAGMA
endif

CPPFLAGS?= -D_GNU_SOURCE
ifndef SYSLIB
CPPFLAGS+= -Iinclude
endif

CDIAGFLAGS+= -Wall
CDIAGFLAGS+= -Wextra
CDIAGFLAGS+= -Werror
CDIAGFLAGS+= -Wchar-subscripts
CDIAGFLAGS+= -Wcomment
CDIAGFLAGS+= -Wformat
CDIAGFLAGS+= -Wformat-security
CDIAGFLAGS+= -Wimplicit
ifndef CENTOS7
CDIAGFLAGS+= -Wimplicit-fallthrough
endif
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
ifdef CENTOS7
CDIAGFLAGS+= -Wno-inline
endif

CLANG?= clang
BPFTOOL?= bpftool
BPF_CC?= $(CLANG)
BPF_ARCH?= bpf # Zig cc calls this bpfel
DOCKER?= docker

# All EEBPF files we track for dependency
EEBPF_FILES:= $(shell find elastic-ebpf)
EEBPF_INCLUDES:= -Ielastic-ebpf/GPL/Events -Ielastic-ebpf/contrib/vmlinux/$(ARCH_ALT)

# LIBQUARK
LIBQUARK_DEPS:= $(wildcard *.h) bpf_probes_skel.h
ifndef SYSLIB
LIBQUARK_DEPS+= $(EEBPF_FILES) include
endif
LIBQUARK_DEPS:= $(filter-out manpages.h, $(LIBQUARK_DEPS))
LIBQUARK_SRCS:=			\
	base64.c		\
	bpf_queue.c		\
	btfhub.c		\
	compat.c		\
	ecs.c			\
	hanson.c		\
	kprobe_queue.c		\
	qbtf.c			\
	quark.c			\
	qutil.c
# CJSON
# We build the source directly as it's just one file
ifndef SYSLIB
LIBQUARK_SRCS+= cJSON.c
endif
LIBQUARK_OBJS:= $(patsubst %.c,%.o,$(LIBQUARK_SRCS))
LIBQUARK_STATIC:= libquark.a
LIBQUARK_STATIC_BIG:= libquark_big.a
# If we are _not_ using system libraries, we link everything with
# _big, so that's our target.
ifndef SYSLIB
LIBQUARK_TARGET=$(LIBQUARK_STATIC_BIG)
else
LIBQUARK_TARGET=$(LIBQUARK_STATIC)
EXTRA_LDFLAGS+= -lbpf -lcjson
endif

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
		$(wildcard libbpf/include/*.[ch])
ifndef SYSLIB
LIBBPF_DEPS+=	$(ELFTOOLCHAIN_FILES)			\
		$(ELFTOOLCHAIN_STATIC)			\
		$(ZLIB_STATIC)
endif
LIBBPF_EXTRA_CFLAGS:= -DQUARK
LIBBPF_EXTRA_CFLAGS+= -fPIC
LIBBPF_EXTRA_CFLAGS+= -I../../elftoolchain/libelf
LIBBPF_EXTRA_CFLAGS+= -I../../elftoolchain/common
LIBBPF_EXTRA_CFLAGS+= -I../../zlib
ifdef CENTOS7
LIBBPF_EXTRA_CFLAGS+= -Wno-address
endif

# BPFPROG (kernel side)
BPFPROG_OBJ:= bpf_probes.o
BPFPROG_DEPS:= bpf_probes.c
ifndef SYSLIB
BPFPROG_DEPS+= $(LIBBPF_DEPS) $(EEBPF_FILES) include
endif

# SVGS
SVGS:= $(patsubst %.dot,%.svg,$(wildcard *.dot))

# DOCS_HTML, matches docs/%.html
DOCS:= $(wildcard *.[378])
DOCS_HTML:= $(patsubst %.3,docs/%.3.html,$(wildcard *.3))
DOCS_HTML+= $(patsubst %.7,docs/%.7.html,$(wildcard *.7))
DOCS_HTML+= $(patsubst %.8,docs/%.8.html,$(wildcard *.8))

all:	$(LIBQUARK_TARGET)		\
	quark-mon			\
	quark-btf			\
	quark-test			\
	quark-kube-talker

$(ZLIB_STATIC): $(ZLIB_FILES)
	$(call assert_no_syslib)
	@cd zlib && CFLAGS="-O3 -fPIC" ./configure --static $(QREDIR)
	@make -C zlib libz.a

$(ELFTOOLCHAIN_STATIC): $(ELFTOOLCHAIN_FILES)
	$(call assert_no_syslib)
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
	$(call assert_no_syslib)
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

bpf_probes_skel.h: $(BPFPROG_OBJ)
	$(call msg,BPFTOOL,bpf_probes_skel.h)
	$(Q)$(BPFTOOL) gen skeleton $(BPFPROG_OBJ) > bpf_probes_skel.h

$(BPFPROG_OBJ): $(BPFPROG_DEPS)
	$(call msg,BPF_CC,$@)
	$(Q)$(BPF_CC)								\
		-g -O2								\
		-target $(BPF_ARCH)						\
		-D__KERNEL__							\
		-D__TARGET_ARCH_$(ARCH_BPF_TARGET)				\
		$(CPPFLAGS)							\
		$(EEBPF_INCLUDES)						\
		-c bpf_probes.c							\
		-o $@

DOCKER_RUN_ARGS=$(QDOCKER)				\
		-v $(PWD):$(PWD)			\
		-w $(PWD)				\
		-u $(shell id -u):$(shell id -g)	\
		quark-builder

docker: docker-image clean-all
	$(call msg,DOCKER-RUN,Dockerfile)
	$(Q)$(DOCKER) run $(DOCKER_RUN_ARGS) $(SHELL) -c "make -C $(PWD) all initramfs.gz"

docker-cross-arm64: clean-all docker-image manpages.h
	$(call msg,DOCKER-RUN,Dockerfile)
	$(Q)$(DOCKER) run				\
		-e ARCH=arm64				\
		-e CC=aarch64-linux-gnu-gcc		\
		-e LD=aarch64-linux-gnu-ld		\
		-e AR=aarch64-linux-gnu-ar		\
		-e GOARCH=arm64				\
		$(DOCKER_RUN_ARGS)			\
		$(SHELL) -c "make -C $(PWD) all initramfs.gz"

docker-image: clean-all
	$(call msg,DOCKER-IMAGE,Dockerfile)
	$(Q)$(DOCKER) build				\
		$(QDOCKER)				\
		-f Dockerfile				\
		-t quark-builder			\
		.

docker-shell:
	$(DOCKER) run -it $(DOCKER_RUN_ARGS) $(SHELL)


CENTOS7_RUN_ARGS=$(QDOCKER)				\
		-v $(PWD):$(PWD)			\
		-w $(PWD)				\
		-u $(shell id -u):$(shell id -g)	\
		-e CENTOS7=y				\
		centos7-quark-builder

centos7: clean-all docker-image centos7-image
	# We first make only bpf_probes.o, bpf_probes_skel.h and quark-kube-talker
	# in the modern Ubuntu image, we can't make those on centos7.
	$(DOCKER) run					\
		$(DOCKER_RUN_ARGS)			\
		$(SHELL) -c "make -C $(PWD) bpf_probes.o bpf_probes_skel.h quark-kube-talker"
	# Now we build the rest of the suite as it won't try to rebuild
	# bpf_probes.o, bpf_probes_skel.h and quark-kube-talker
	$(DOCKER) run					\
		$(CENTOS7_RUN_ARGS)			\
		$(SHELL) -c "make -j1 -C $(PWD)"

centos7-image: clean-all
	$(call msg,DOCKER-IMAGE,Dockerfile.centos7)
	$(DOCKER) build					\
		$(QDOCKER)				\
		-f Dockerfile.centos7			\
		-t centos7-quark-builder		\
		.

centos7-shell:
	$(DOCKER) run -it $(CENTOS7_RUN_ARGS) $(SHELL)

ALPINE_RUN_ARGS=$(QDOCKER)				\
		-v $(PWD):$(PWD)			\
		-w $(PWD)				\
		-u $(shell id -u):$(shell id -g)	\
		alpine-quark-builder

alpine: alpine-image clean-all
	$(call msg,ALPINE-DOCKER-RUN,Dockerfile)
	$(Q)$(DOCKER) run 				\
		$(ALPINE_RUN_ARGS) $(SHELL)		\
		-c "make -C $(PWD) all initramfs.gz"

alpine-image: clean-all
	$(call msg,ALPINE-IMAGE,Dockerfile.alpine)
	$(Q)$(DOCKER) build				\
		$(QDOCKER)				\
		-f Dockerfile.alpine			\
		-t alpine-quark-builder			\
		.

include: $(LIBBPF_DEPS) cJSON.h
	$(call msg,make,include)
	$(Q)make -C $(LIBBPF_SRC)					\
		NO_PKG_CONFIG=y						\
		install_headers INCLUDEDIR=../../include $(QREDIR)
	$(Q)make -C $(LIBBPF_SRC)					\
		NO_PKG_CONFIG=y						\
		install_uapi_headers UAPIDIR=../../include $(QREDIR)
	$(Q)install -D -m 444 cJSON.h include/cjson/cJSON.h
	$(Q)touch include

%.svg: %.dot
	$(call msg,DOT,$@)
	$(Q)dot -Tsvg $< -o $@

svg: $(SVGS)

test: quark-test
	$(SUDO) ./quark-test

test-kernel: initramfs.gz
	./ktest-all.sh

#
# We force QUARK_BTF_PATH when testing under valgrind. This forces
# libbpf to *not* attempt to load additional BTF from kernel modules.
# Libbpf does BPF commands that valgrind doesn't understand when
# loading these BTF modules, making valgrind spit thousands of false
# positives.
#
test-valgrind: quark-test
	$(SUDO) QUARK_BTF_PATH=/sys/kernel/btf/vmlinux			\
		valgrind						\
		--trace-children=no					\
		--child-silent-after-fork=yes				\
		./quark-test -1						\
		2>&1
# | grep -v "^--.*WARNING: unhandled eBPF command"

initramfs:
	mkdir -p initramfs/bin

initramfs.gz: init quark-mon-static quark-btf-static quark-test-static true initramfs
	$(call assert_no_syslib)
	cp init initramfs/
	cp quark-mon-static initramfs/quark-mon
	cp quark-btf-static initramfs/quark-btf
	cp quark-test-static initramfs/quark-test
	cp quark-test-static initramfs/quark-test
	cp true initramfs/bin
	cd initramfs && find . -print0 | cpio -0 -ov --format=newc | gzip -9 > ../$@

init: init.c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) -static -o $@ $^

true: true.c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) -static -o $@ $^

quark-mon: quark-mon.c manpages.h $(LIBQUARK_TARGET)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) \
		-o $@ $< $(LIBQUARK_TARGET) $(EXTRA_LDFLAGS)

quark-btf: quark-btf.c manpages.h $(LIBQUARK_TARGET)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) \
		-o $@ $< $(LIBQUARK_TARGET) $(EXTRA_LDFLAGS)

quark-test: quark-test.c manpages.h $(LIBQUARK_TARGET)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) \
		-o $@ $< $(LIBQUARK_TARGET) $(EXTRA_LDFLAGS)

quark-mon-static: quark-mon.c manpages.h $(LIBQUARK_STATIC_BIG)
	$(call msg,CC,$@)
	$(call assert_no_syslib)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -DNO_PRIVDROP $(CDIAGFLAGS) \
		-static -o $@ $< $(LIBQUARK_STATIC_BIG) $(EXTRA_LDFLAGS)

quark-btf-static: quark-btf.c manpages.h $(LIBQUARK_STATIC_BIG)
	$(call msg,CC,$@)
	$(call assert_no_syslib)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) \
		-static -o $@ $< $(LIBQUARK_STATIC_BIG) $(EXTRA_LDFLAGS)

quark-test-static: quark-test.c manpages.h $(LIBQUARK_STATIC_BIG)
	$(call msg,CC,$@)
	$(call assert_no_syslib)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) \
		-static -o $@ $< $(LIBQUARK_STATIC_BIG) $(EXTRA_LDFLAGS)

quark-kube-talker: quark-kube-talker.go go.mod
	$(call msg,GO,$@)
	$(Q)$(GO) build -o $@ quark-kube-talker.go $(QREDIR)

man-embedder: man-embedder.c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(CDIAGFLAGS) -o $@ $^

manpages.h: man-embedder display_man.c quark-btf.8 quark-mon.8 quark-test.8
	$(Q)echo '// SPDX-License-Identifier: Apache-2.0' > $@
	$(Q)echo '/* Copyright (c) 2024 Elastic NV */' >> $@
	$(Q)echo '' >> $@
	$(call msg,MAN-EMB,quark-btf.8)
	$(Q)./man-embedder quark-btf.8 MAN_QUARK_BTF >> $@
	$(call msg,MAN-EMB,quark-mon.8)
	$(Q)./man-embedder quark-mon.8 MAN_QUARK_MON >> $@
	$(call msg,MAN-EMB,quark-test.8)
	$(Q)./man-embedder quark-test.8 MAN_QUARK_TEST >> $@
	$(call msg,MAN-EMB,display_man.c)
	$(Q)cat display_man.c >> $@

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

README.md: docs/quark.7.html
	$(if $(shell which $(HTML2MARKDOWN) 2>/dev/null),,		\
		$(error cant find $(HTML2MARKDOWN), available at	\
		https://github.com/JohannesKaufmann/html-to-markdown/releases))
	$(call msg,MARKDOWN,$<)
	$(Q)$(HTML2MARKDOWN) < $< > $@
	$(call msg,MASSAGE,$@)
	$(Q)$(foreach m,$(DOCS),					\
		sed -i 's/$(m).html/https:\/\/elastic.github.io\/quark\/$(m).html/g' $@;)
	$(Q)sed -i '1,4d' $@
	$(Q)sed -i '1s/^/# /' $@
	$(Q)sed -i '/^# TABLE OF CONTENTS/{N;d}' $@
	$(Q)sed -i 's/`quark`/quark/g' $@
	$(Q)sed -i '$$ d' $@
	$(Q)sed -i '$$ d' $@


docs: $(DOCS_HTML) docs/index.html README.md

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
	$(Q)rm -f			\
		*.o			\
		*.a			\
		man-embedder		\
		manpages.h		\
		quark-mon		\
		quark-mon-static	\
		quark-btf		\
		quark-btf-static	\
		quark-test		\
		quark-test-static	\
		quark-kube-talker	\
		true			\
		btf_prog_skel.h		\
		init
	$(Q)rm -rf initramfs

clean-all: clean
	$(call msg,CLEAN-ALL)
	$(Q)rm -f $(SVGS)
	$(Q)rm -rf include
	$(Q)rm -f initramfs.gz
	$(Q)make -C $(LIBBPF_SRC) clean NO_PKG_CONFIG=y
	$(Q)make -C $(ELFTOOLCHAIN_SRC)/libelf clean
	$(Q)make -C $(ZLIB_SRC) clean || true
	$(Q)rm -f $(ZLIB_SRC)/{Makefile,zconf.h,configure.log}

clean-docs:
	$(call msg,CLEAN,docs)
	$(Q)rm -f docs/*.html

.PHONY:				\
	all			\
	btfhub			\
	centos7			\
	centos7-image		\
	centos7-shell		\
	clean			\
	clean-all		\
	clean-docs		\
	docs			\
	docker			\
	docker-cross-arm64	\
	docker-image		\
	docker-shell		\
	eebpf-sync		\
	test			\
	test-kernel		\
	test-valgrind

.NOTPARALLEL:			\
	clean			\
	clean-all		\
	centos7			\
	centos7-image		\
	centos7-shell		\
	docker			\
	docker-cross-arm64	\
	docker-image		\
	docker-shell		\
	initramfs.gz		\
	test			\
	test-kernel		\
	test-valgrind

.SUFFIXES:
