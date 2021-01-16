/*
 * Copyright (c) 2020 Duncan Overbruck <mail@duncano.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

#if HAVE_CRYPT_H
#	include <crypt.h>
#endif
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#ifdef HAVE_READPASSPHRASE
#	include <readpassphrase.h>
#else
#	include "sys-readpassphrase.h"
#endif
#include <shadow.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "openbsd.h"
#include "doas.h"

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

void
shadowauth(const char *myname, int persist)
{
	const char *hash;
	char *encrypted;
	struct passwd *pw;
	char *challenge, *response, rbuf[1024], cbuf[128];

#ifdef USE_TIMESTAMP
	int fd = -1;
	int valid = 0;

	if (persist)
		fd = timestamp_open(&valid, 5 * 60);
	if (fd != -1 && valid == 1)
		goto good;
#else
	(void) persist;
#endif

	if ((pw = getpwnam(myname)) == NULL)
		err(1, "getpwnam");

	hash = pw->pw_passwd;
	if (hash[0] == 'x' && hash[1] == '\0') {
		struct spwd *sp;
		if ((sp = getspnam(myname)) == NULL)
			errx(1, "Authentication failed");
		hash = sp->sp_pwdp;
	} else if (hash[0] != '*') {
		errx(1, "Authentication failed");
	}

	char host[HOST_NAME_MAX + 1];
	if (gethostname(host, sizeof(host)))
		snprintf(host, sizeof(host), "?");
	snprintf(cbuf, sizeof(cbuf),
			"\rdoas (%.32s@%.32s) password: ", myname, host);
	challenge = cbuf;

	response = readpassphrase(challenge, rbuf, sizeof(rbuf), RPP_REQUIRE_TTY);
	if (response == NULL && errno == ENOTTY) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
			"tty required for %s", myname);
		errx(1, "a tty is required");
	}
	if (response == NULL)
		err(1, "readpassphrase");
	if ((encrypted = crypt(response, hash)) == NULL) {
		explicit_bzero(rbuf, sizeof(rbuf));
		errx(1, "Authentication failed");
	}
	explicit_bzero(rbuf, sizeof(rbuf));
	if (strcmp(encrypted, hash) != 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed auth for %s", myname);
		errx(1, "Authentication failed");
	}

#ifdef USE_TIMESTAMP
good:
	if (fd != -1) {
		timestamp_set(fd, 5 * 60);
		close(fd);
	}
#endif
}
