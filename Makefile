#	$OpenBSD: Makefile,v 1.9 2014/01/13 01:41:00 tedu Exp $

SRCS=	parse.y doas.c

PROG=	doas
MAN=	doas.1 doas.conf.5

BINOWN= root
BINGRP= wheel
BINMODE=4555

COPTS+= -Wall -Wextra -Werror -pedantic -std=c11
CFLAGS+= -I${CURDIR} -I${CURDIR}/libopenbsd ${COPTS}

BINDIR?=/usr/bin
MANDIR?=/usr/share/man

default: ${PROG}

OBJS:=${SRCS:.y=.c}
OBJS:=${OBJS:.c=.o}

${PROG}: ${OBJS}
	${CC} ${COPTS} ${LDOPTS} $^ -o $@

${BINDIR}/${PROG}: ${PROG}
	cp $< $@
	chown ${BINOWN}:${BINGRP} $@
	chmod ${BINMODE} $@

install: ${BINDIR}/${PROG}

clean:
	rm -f ${OBJS}
	rm -f ${PROG}

.PHONY: default clean install
