# Copyright 2015 Nathan Holstein

BINDIR?=/usr/bin
MANDIR?=/usr/share/man

default: ${PROG}

OPENBSD:=reallocarray.c strtonum.c execvpe.c setresuid.c \
	auth_userokay.c setusercontext.c explicit_bzero.c
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
	chmod ${BINMODE} $@
	chown ${BINOWN}:${BINGRP} $@

${BINDIR}:
	mkdir -pm 0755 $@

${BINDIR}/${PROG}: .${PROG}.chmod ${BINDIR}
	mv $< $@

VERSION:=\#define VERSION "$(shell git describe --dirty --tags --long --always)"
OLDVERSION:=$(shell [ -f version.h ] && cat version.h)
version.h: ; @echo '$(VERSION)' > $@
ifneq ($(VERSION),$(OLDVERSION))
.PHONY: version.h
endif

MAN:=$(join $(addprefix ${MANDIR}/man,$(patsubst .%,%/,$(suffix ${MAN}))),${MAN})
$(foreach M,${MAN},$(eval $M: $(notdir $M); cp $$< $$@))

install: ${BINDIR}/${PROG} ${MAN}

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
