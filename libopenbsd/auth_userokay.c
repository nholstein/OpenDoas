/*
 * Copyright (c) 2015 Nathan Holstein <nathan.holstein@gmail.com>
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

#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#include <readpassphrase.h>
#include <stdio.h>
#include <stdlib.h>

#include <security/pam_appl.h>

#include "openbsd.h"

#define PAM_SERVICE "sudo"

#define __UNUSED __attribute__ ((unused))

static int
pam_conv(__UNUSED int huh, __UNUSED const struct pam_message **msg,
		__UNUSED struct pam_response **rsp, __UNUSED void *ptr)
{
	return 0;
}

static struct pam_conv conv = {
	.conv = pam_conv,
	.appdata_ptr = NULL,
};

static int
check_pam(const char *user)
{
	fprintf(stderr, "check_pam(%s)\n", user);

	int ret;
	pam_handle_t *pamh = NULL;

	ret = pam_start(PAM_SERVICE, user, &conv, &pamh);
	if (ret != 0) {
		fprintf(stderr, "pam_start(\"%s\", \"%s\", ?, ?): failed\n",
				PAM_SERVICE, user);
		return -1;
	}

	if ((ret = pam_close_session(pamh, 0)) != 0) {
		fprintf(stderr, "pam_close_session(): %s\n", pam_strerror(pamh, ret));
		return -1;
	}

	return 0;
}

int
auth_userokay(char *name, char *style, char *type, char *password)
{
	if (!name)
		return 0;
	if (style || type || password) {
		fprintf(stderr, "auth_userokay(name, NULL, NULL, NULL)!\n");
		exit(1);
	}

	int ret = check_pam(name);
	if (ret != 0) {
		fprintf(stderr, "PAM authentication failed\n");
		return 0;
	}

	/*
	char passbuf[256];
	if (readpassphrase("Password: ", passbuf, sizeof(passbuf),
			RPP_REQUIRE_TTY) == NULL)
		return 0;

	explicit_bzero(passbuf, sizeof(passbuf));
	*/

	fprintf(stderr, "failing auth check for %s\n", name);
	return 0;
}

