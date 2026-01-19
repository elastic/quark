FROM ubuntu:24.04
ENV BPFTOOL="/usr/lib/linux-tools/6.11.0-26-generic/bpftool"
ENV HOME=/tmp/quark-builder
RUN apt-get update && apt-get install -y		\
	bison						\
	clang						\
	cpio						\
	gcc						\
	golang						\
	gcc-aarch64-linux-gnu				\
	linux-tools-6.11.0-26-generic			\
	make						\
	m4
