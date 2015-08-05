#	$OpenBSD: Makefile,v 1.9 2014/01/13 01:41:00 tedu Exp $
#
# Copyright 2015 Nathan Holstein

SRCS=	parse.y doas.c

PROG=	doas
MAN=	doas.1 doas.conf.5

BINOWN= root
BINGRP= wheel
BINMODE=4511

COPTS+= -Wall -Wextra -Werror -pedantic -std=c11
CFLAGS+= -I${CURDIR} -I${CURDIR}/libopenbsd ${COPTS}
LDFLAGS+= -lpam

BINDIR?=/usr/bin
MANDIR?=/usr/share/man

default: ${PROG}

OPENBSD:=reallocarray.c strtonum.c execvpe.c setresuid.c \
	auth_userokay.c setusercontext.c explicit_bzero.c
OPENBSD:=$(addprefix libopenbsd/,${OPENBSD:.c=.o})
libopenbsd.a: ${OPENBSD}
	${AR} -r $@ $?

OBJS:=${SRCS:.y=.c}
OBJS:=${OBJS:.c=.o}

${PROG}: ${OBJS} libopenbsd.a
	${CC} ${CFLAGS} ${LDFLAGS} $^ -o $@

.%.chmod: %
	cp $< $@
	chmod ${BINMODE} $@
	chown ${BINOWN}:${BINGRP} $@

${BINDIR}:
	mkdir -pm 0755 $@

${BINDIR}/${PROG}: .${PROG}.chmod ${BINDIR}
	mv $< $@

MAN:=$(join $(addprefix ${MANDIR}/man,$(patsubst .%,%/,$(suffix ${MAN}))),${MAN})
$(foreach M,${MAN},$(eval $M: $(notdir $M); cp $$< $$@))

install: ${BINDIR}/${PROG} ${MAN}

clean:
	rm -f libopenbsd.a
	rm -f ${OPENBSD}
	rm -f ${OBJS}
	rm -f ${PROG}

.PHONY: default clean install man
.INTERMEDIATE: .${PROG}.chmod
