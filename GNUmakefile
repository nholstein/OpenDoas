PROG=	doas
MAN=	doas.1 doas.conf.5

SRCS=	parse.y doas.c env.c

include config.mk

CFLAGS+= -I. -Ilibopenbsd ${COPTS}
COPTS+=	-Wall -Wextra -pedantic -O2 -D_FORTIFY_SOURCE=2
YFLAGS=

all: ${PROG}

OBJS:=	${SRCS:.y=.c}
OBJS:=	${OBJS:.c=.o}

${PROG}: ${OBJS}
	${CC} ${CFLAGS} $^ -o $@ ${LDFLAGS} ${LDLIBS}

install: ${PROG} ${PAM_DOAS} ${MAN}
	mkdir -p -m 0755 ${DESTDIR}${BINDIR}
	[ -n "${PAM_DOAS}" ] && mkdir -p -m 0755 ${DESTDIR}${PAMDIR} || true
	mkdir -p -m 0755 ${DESTDIR}${MANDIR}/man1
	mkdir -p -m 0755 ${DESTDIR}${MANDIR}/man5
	cp -f ${PROG} ${DESTDIR}${BINDIR}
	chown ${BINOWN}:${BINGRP} ${DESTDIR}${BINDIR}/${PROG}
	chmod ${BINMODE} ${DESTDIR}${BINDIR}/${PROG}
	[ -n "${PAM_DOAS}" ] && cp ${PAM_DOAS} ${DESTDIR}${PAMDIR}/doas || true
	[ -n "${PAM_DOAS}" ] && chmod 0644 ${DESTDIR}${PAMDIR}/doas || true
	cp -f doas.1 ${DESTDIR}${MANDIR}/man1
	cp -f doas.conf.5 ${DESTDIR}${MANDIR}/man5

uninstall:
	rm -f ${DESTDIR}${BINDIR}/${PROG}
	rm -f ${DESTDIR}${PAMDIR}/doas
	rm -f ${DESTDIR}${MANDIR}/man1/doas.1
	rm -f ${DESTDIR}${MANDIR}/man5/doas.conf.5

clean:
	rm -f ${PROG} ${OBJS} ${OBJS:.o=.d} parse.c

-include ${OBJS:.o=.d}

.PHONY: all clean install uninstall
