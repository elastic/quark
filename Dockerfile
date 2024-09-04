# aka 24.04
FROM ubuntu:noble
ENV BPFTOOL="/usr/lib/linux-tools-6.8.0-41/bpftool"
RUN apt-get update && apt-get install -y		\
	clang						\
	gcc						\
	gcc-aarch64-linux-gnu				\
	linux-tools-6.8.0-41-generic			\
	make						\
	m4
