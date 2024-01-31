CFLAGS?= -g -O2
CFLAGS+= -fno-strict-aliasing
CFLAGS+= -Wall
CFLAGS+= -Wextra
CFLAGS+= -Werror
CFLAGS+= -Wchar-subscripts
CFLAGS+= -Wcomment
CFLAGS+= -Wformat
CFLAGS+= -Wformat-security
CFLAGS+= -Wimplicit
CFLAGS+= -Winline
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wparentheses
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wreturn-type
CFLAGS+= -Wshadow
CFLAGS+= -Wsign-compare
CFLAGS+= -Wstrict-prototypes
CFLAGS+= -Wswitch
CFLAGS+= -Wtrigraphs
CFLAGS+= -Wuninitialized
CFLAGS+= -Wunused
CFLAGS+= -Wno-unused-parameter

LDFLAGS?= -lbsd
CC?= cc
SRCS:= $(wildcard *.c)
PROGS:= $(patsubst %.c,%,$(SRCS))

%: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

.PHONY: all
all: $(PROGS)
