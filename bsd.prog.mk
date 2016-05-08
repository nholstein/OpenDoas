# Copyright 2015 Nathan Holstein

default: ${PROG}

include config.mk

OPENBSD:=$(addprefix libopenbsd/,${OPENBSD:.c=.o})
libopenbsd.a: ${OPENBSD}
	${AR} -r $@ $?

CFLAGS:=${CFLAGS} -I${CURDIR}/libopenbsd ${COPTS} -MD -MP

OBJS:=${SRCS:.y=.c}
OBJS:=${OBJS:.c=.o}

${PROG}: ${OBJS} libopenbsd.a
	${CC} ${CFLAGS} ${LDFLAGS} $^ -o $@

install: ${PROG} ${PAM_DOAS}
	mkdir -p -m 0755 ${DESTDIR}${BINDIR}
	mkdir -p -m 0755 ${DESTDIR}${PAMDIR}
	mkdir -p -m 0755 ${DESTDIR}${MANDIR}/man1
	mkdir -p -m 0755 ${DESTDIR}${MANDIR}/man5
	cp -f ${PROG} ${DESTDIR}${BINDIR}
	chown ${BINOWN}:${BINGRP} ${DESTDIR}${BINDIR}/${PROG}
	chmod ${BINMODE} ${DESTDIR}${BINDIR}/${PROG}
	cp ${PAM_DOAS} ${DESTDIR}${PAMDIR}/doas
	chmod 0644 ${DESTDIR}${PAMDIR}/doas
	cp -f doas.1 ${DESTDIR}${MANDIR}/man1
	cp -f doas.conf.5 ${DESTDIR}${MANDIR}/man5

clean:
	rm -f version.h
	rm -f libopenbsd.a
	rm -f ${OPENBSD}
	rm -f ${OPENBSD:.o=.d}
	rm -f ${OBJS}
	rm -f ${OBJS:.o=.d}
	rm -f ${PROG}

-include ${objs:.o=.d} ${OPENBSD:.o=.d}

.PHONY: default clean install man
.INTERMEDIATE: .${PROG}.chmod
