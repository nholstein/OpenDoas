#	$OpenBSD: Makefile,v 1.9 2014/01/13 01:41:00 tedu Exp $

SRCS=	parse.y doas.c

PROG=	doas
MAN=	doas.1 doas.conf.5

BINOWN= root
BINGRP= wheel
BINMODE=4511

CFLAGS+= -I${CURDIR}
COPTS+= -Wall -Wextra -Werror -pedantic -std=c11
LDFLAGS+= -lpam

include bsd.prog.mk
