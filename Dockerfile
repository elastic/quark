FROM ubuntu:26.04
ENV HOME=/tmp/quark-builder
RUN apt-get update && apt-get install -y		\
	bison						\
	bpftool                                         \
	clang						\
	cpio						\
	gcc						\
	golang						\
	gcc-aarch64-linux-gnu				\
	make						\
	m4
