FROM ubuntu:24.04
ENV BPFTOOL="/usr/lib/linux-tools/6.11.0-26-generic/bpftool"
RUN apt-get update && apt-get install -y		\
	clang						\
	cpio						\
	gcc						\
	gcc-aarch64-linux-gnu				\
	linux-tools-6.11.0-26-generic			\
	make						\
	m4
