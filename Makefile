#	$OpenBSD: Makefile,v 1.9 2014/01/13 01:41:00 tedu Exp $

SRCS=	parse.y doas.c

PROG=	doas
MAN=	doas.1 doas.conf.5

BINOWN= root
BINMODE=4555

CFLAGS+= -I${.CURDIR}
COPTS+=	-Wall

.include <bsd.prog.mk>
