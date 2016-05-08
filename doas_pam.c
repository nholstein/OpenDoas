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
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#include <security/pam_appl.h>

#include "doas.h"
#include "includes.h"

#define PAM_SERVICE_NAME "doas"

static pam_handle_t *pamh = NULL;
static sig_atomic_t volatile caught_signal = 0;

static char *
prompt(const char *msg, int echo_on, int *pam)
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
doas_pam_conv(int nmsgs, const struct pam_message **msgs,
		struct pam_response **rsps, __UNUSED void *ptr)
{
	struct pam_response *rsp;
	int i, style;
	int ret = PAM_SUCCESS;

	if (!(rsp = calloc(nmsgs, sizeof(struct pam_response))))
		errx(1, "couldn't malloc pam_response");

	for (i = 0; i < nmsgs; i++) {
		switch (style = msgs[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			rsp[i].resp = prompt(msgs[i]->msg, style == PAM_PROMPT_ECHO_ON, &ret);
			if (ret != PAM_SUCCESS)
				goto fail;
			break;

		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			if (fprintf(style == PAM_ERROR_MSG ? stderr : stdout,
					"%s\n", msgs[i]->msg) < 0)
				goto fail;
			break;

		default:
			errx(1, "invalid PAM msg_style %d", style);
		}
	}

	*rsps = rsp;
	rsp = NULL;

	return PAM_SUCCESS;

fail:
	/* overwrite and free response buffers */
	for (i = 0; i < nmsgs; i++) {
		if (rsp[i].resp == NULL)
			continue;
		switch (style = msgs[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			explicit_bzero(rsp[i].resp, strlen(rsp[i].resp));
			free(rsp[i].resp);
		}
		rsp[i].resp = NULL;
	}

	return PAM_CONV_ERR;
}

static void
catchsig(int sig)
{
	caught_signal = sig;
}

int
doas_pam(char *name, int interactive, int nopass)
{
	static const struct pam_conv conv = {
		.conv = doas_pam_conv,
		.appdata_ptr = NULL,
	};
	const char *ttydev, *tty;
	pid_t child;
	int ret;

	if (!name)
		return 0;

	ret = pam_start(PAM_SERVICE_NAME, name, &conv, &pamh);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_start(\"%s\", \"%s\", ?, ?): failed\n",
				PAM_SERVICE_NAME, name);

	ret = pam_set_item(pamh, PAM_USER, name);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_set_item(?, PAM_USER, \"%s\"): %s\n",
				name, pam_strerror(pamh, ret));

	ret = pam_set_item(pamh, PAM_RUSER, name);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_set_item(?, PAM_RUSER, \"%s\"): %s\n",
				name, pam_strerror(pamh, ret));

	if (isatty(0) && (ttydev = ttyname(0)) != NULL) {
		if (strncmp(ttydev, "/dev/", 5))
			tty = ttydev + 5;
		else
			tty = ttydev;

		ret = pam_set_item(pamh, PAM_TTY, tty);
		if (ret != PAM_SUCCESS)
			errx(1, "pam_set_item(?, PAM_TTY, \"%s\"): %s\n",
					tty, pam_strerror(pamh, ret));
	}

	if (!nopass) {
		if (!interactive)
			errx(1, "Authorization required");
		/* authenticate */
		ret = pam_authenticate(pamh, 0);
		if (ret != PAM_SUCCESS) {
			ret = pam_end(pamh, ret);
			if (ret != PAM_SUCCESS)
				errx(1, "pam_end(): %s\n", pam_strerror(pamh, ret));
			return 0;
		}
	}

	ret = pam_setcred(pamh, PAM_ESTABLISH_CRED);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_setcred(?, PAM_ESTABLISH_CRED): %s\n",
				pam_strerror(pamh, ret));

	ret = pam_acct_mgmt(pamh, 0);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_setcred(): %s\n", pam_strerror(pamh, ret));

	/* open session */
	ret = pam_open_session(pamh, 0);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_open_session(): %s\n", pam_strerror(pamh, ret));

	if ((child = fork()) == -1) {
		ret = pam_close_session(pamh, 0);
		if (ret != PAM_SUCCESS)
			errx(1, "pam_close_session(): %s\n", pam_strerror(pamh, ret));

		ret = pam_end(pamh, PAM_ABORT);
		if (ret != PAM_SUCCESS)
			errx(1, "pam_end(): %s\n", pam_strerror(pamh, ret));

		errx(1, "fork()");
	}

	/* return as child */
	if (child == 0) {
		return 1;
	}

	/* parent watches for signals and closes session */
	sigset_t sigs;
	struct sigaction act, oldact;
	int status;

	/* block signals */
	sigfillset(&sigs);
	if (sigprocmask(SIG_BLOCK, &sigs, NULL)) {
		errx(1, "sigprocmask()");
	}

	/* setup signal handler */
	act.sa_handler = catchsig;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigemptyset(&sigs);

	/* unblock SIGTERM and SIGALRM to catch them */
	if(sigaddset(&sigs, SIGTERM) ||
			sigaddset(&sigs, SIGALRM) ||
			sigaction(SIGTERM, &act, &oldact) ||
			sigprocmask(SIG_UNBLOCK, &sigs, NULL)) {
		errx(1, "failed to set signal handler");
	}

	/* wait for child to be terminated */
	if (waitpid(child, &status, 0) != -1) {
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "%s%s\n", strsignal(WTERMSIG(status)),
					WCOREDUMP(status) ? " (core dumped)" : "");
			status = WTERMSIG(status) + 128;
		} else {
			status = WEXITSTATUS(status);
		}
	}
	else if (caught_signal)
		status = caught_signal + 128;
	else
		status = 1;

	if (caught_signal) {
		fprintf(stderr, "\nSession terminated, killing shell\n");
		kill(child, SIGTERM);
	}

	/* close session */
	ret = pam_close_session(pamh, 0);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_close_session(): %s\n", pam_strerror(pamh, ret));

	ret = pam_end(pamh, PAM_SUCCESS);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_end(): %s\n", pam_strerror(pamh, ret));

	if (caught_signal) {
		/* kill child */
		sleep(2);
		kill(child, SIGKILL);
		fprintf(stderr, " ...killed.\n");

		/* unblock cached signal and resend */
		sigaction(SIGTERM, &oldact, NULL);
		if (caught_signal != SIGTERM)
			caught_signal = SIGKILL;
		kill(getpid(), caught_signal);
	}

	exit(status);

	return 0;
}
