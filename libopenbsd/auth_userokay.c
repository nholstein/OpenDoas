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
#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

#include "includes.h"

#define PAM_SERVICE_NAME "doas"

static char *
pam_prompt(const char *msg, int echo_on, int *pam)
{
	char buf[PAM_MAX_RESP_SIZE];
	int flags = RPP_REQUIRE_TTY | (echo_on ? RPP_ECHO_ON : RPP_ECHO_OFF);
	char *ret = readpassphrase(msg, buf, sizeof(buf), flags);
	if (!ret)
		*pam = PAM_CONV_ERR;
	else if (!(ret = strdup(ret)))
		*pam = PAM_BUF_ERR;
	explicit_bzero(buf, sizeof(buf));
	return ret;
}

static int
pam_conv(int nmsgs, const struct pam_message **msgs,
		struct pam_response **rsps, __UNUSED void *ptr)
{
	struct pam_response *rsp;
	int i, style;
	int pam = PAM_SUCCESS;

	if (!(rsp = calloc(nmsgs, sizeof(struct pam_response))))
		errx(1, "couldn't malloc pam_response");
	*rsps = rsp;

	for (i = 0; i < nmsgs; i++) {
		switch (style = msgs[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			rsp[i].resp = pam_prompt(msgs[i]->msg,
					style == PAM_PROMPT_ECHO_ON, &pam);
			break;

		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			if (fprintf(style == PAM_ERROR_MSG ? stderr : stdout,
					"%s\n", msgs[i]->msg) < 0)
				pam = PAM_CONV_ERR;
			break;

		default:
			errx(1, "invalid PAM msg_style %d", style);
		}
	}

	return PAM_SUCCESS;
}

int
auth_userokay(char *name, char *style, char *type, char *password)
{
	static const struct pam_conv conv = {
		.conv = pam_conv,
		.appdata_ptr = NULL,
	};

	int ret, auth;
	pam_handle_t *pamh = NULL;

	if (!name)
		return 0;
	if (style || type || password)
		errx(1, "auth_userokay(name, NULL, NULL, NULL)!\n");

	ret = pam_start(PAM_SERVICE_NAME, name, &conv, &pamh);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_start(\"%s\", \"%s\", ?, ?): failed\n",
				PAM_SERVICE_NAME, name);

	auth = pam_authenticate(pamh, 0);

	ret = pam_open_session(pamh, 0);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_open_session(): %s\n", pam_strerror(pamh, ret));

	ret = pam_close_session(pamh, 0);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_close_session(): %s\n", pam_strerror(pamh, ret));

	return auth == PAM_SUCCESS;
}
