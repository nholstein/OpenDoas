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

.%.chmod: %
	cp $< $@
	chown ${BINOWN}:${BINGRP} $@
	chmod ${BINMODE} $@

${DESTRDIR}${BINDIR} ${DESTRDIR}${PAMDIR}:
	mkdir -pm 0755 $@

${DESTDIR}${BINDIR}/${PROG}: .${PROG}.chmod ${BINDIR}
	mv $< $@

${DESTDIR}${PAMDIR}/doas: ${PAM_DOAS}
	cp $< $@

VERSION:=\#define VERSION "$(shell git describe --dirty --tags --long --always)"
OLDVERSION:=$(shell [ -f version.h ] && cat version.h)
version.h: ; @echo '$(VERSION)' > $@
ifneq ($(VERSION),$(OLDVERSION))
.PHONY: version.h
endif

MAN:=$(join $(addprefix ${DESTDIR}${MANDIR}/man,$(patsubst .%,%/,$(suffix ${MAN}))),${MAN})
$(foreach M,${MAN},$(eval $M: $(notdir $M); cp $$< $$@))

install: ${DESTDIR}${BINDIR}/${PROG} ${DESTDIR}${PAMDIR}/doas ${MAN}

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
