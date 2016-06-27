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
#ifdef __linux__
#include <limits.h>
#endif

#include <security/pam_appl.h>

#include "doas.h"
#include "includes.h"

#define PAM_SERVICE_NAME "doas"

static pam_handle_t *pamh = NULL;
static char doas_prompt[128];
static sig_atomic_t volatile caught_signal = 0;
static int session_opened = 0;
static int cred_established = 0;

static void
catchsig(int sig)
{
	caught_signal = sig;
}

static char *
pamprompt(const char *msg, int echo_on, int *ret)
{
	const char *prompt;
	char *pass, buf[PAM_MAX_RESP_SIZE];
	int flags = RPP_REQUIRE_TTY | (echo_on ? RPP_ECHO_ON : RPP_ECHO_OFF);

	/* overwrite default prompt if it matches "Password:[ ]" */
	if (strncmp(msg,"Password:", 9) == 0 &&
	    (msg[9] == '\0' || (msg[9] == ' ' && msg[10] == '\0')))
		prompt = doas_prompt;
	else
		prompt = msg;

	pass = readpassphrase(prompt, buf, sizeof(buf), flags);
	if (!pass)
		*ret = PAM_CONV_ERR;
	else if (!(pass = strdup(pass)))
		*ret = PAM_BUF_ERR;
	else
		*ret = PAM_SUCCESS;

	explicit_bzero(buf, sizeof(buf));
	return pass;
}

static int
pamconv(int nmsgs, const struct pam_message **msgs,
		struct pam_response **rsps, __UNUSED void *ptr)
{
	struct pam_response *rsp;
	int i, style;
	int ret;

	if (!(rsp = calloc(nmsgs, sizeof(struct pam_response))))
		errx(1, "couldn't malloc pam_response");

	for (i = 0; i < nmsgs; i++) {
		switch (style = msgs[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			rsp[i].resp = pamprompt(msgs[i]->msg, style == PAM_PROMPT_ECHO_ON, &ret);
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

void
pamcleanup(int ret)
{
	if (session_opened != 0) {
		ret = pam_close_session(pamh, 0);
		if (ret != PAM_SUCCESS)
			errx(1, "pam_close_session: %s", pam_strerror(pamh, ret));
	}
	if (cred_established != 0) {
		ret = pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);
		if (ret != PAM_SUCCESS)
			warn("pam_setcred(?, PAM_DELETE_CRED | PAM_SILENT): %s",
			    pam_strerror(pamh, ret));
	}
	pam_end(pamh, ret);
}

void
watchsession(pid_t child)
{
	sigset_t sigs;
	struct sigaction act, oldact;
	int status;

	/* block signals */
	sigfillset(&sigs);
	if (sigprocmask(SIG_BLOCK, &sigs, NULL)) {
		warn("failed to block signals");
		caught_signal = 1;
		goto close;
	}

	/* setup signal handler */
	act.sa_handler = catchsig;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	/* unblock SIGTERM and SIGALRM to catch them */
	sigemptyset(&sigs);
	if (sigaddset(&sigs, SIGTERM) ||
	    sigaddset(&sigs, SIGALRM) ||
	    sigaddset(&sigs, SIGTSTP) ||
	    sigaction(SIGTERM, &act, &oldact) ||
	    sigprocmask(SIG_UNBLOCK, &sigs, NULL)) {
		warn("failed to set signal handler");
		caught_signal = 1;
		goto close;
	}

	/* wait for child to be terminated */
	if (waitpid(child, &status, 0) != -1) {
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "%s%s\n", strsignal(WTERMSIG(status)),
					WCOREDUMP(status) ? " (core dumped)" : "");
			status = WTERMSIG(status) + 128;
		} else
			status = WEXITSTATUS(status);
	}
	else if (caught_signal)
		status = caught_signal + 128;
	else
		status = 1;

close:
	if (caught_signal) {
		fprintf(stderr, "\nSession terminated, killing shell\n");
		kill(child, SIGTERM);
	}

	pamcleanup(PAM_SUCCESS);

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
}

int
pamauth(const char *user, const char* ruser, int interactive, int nopass)
{
	static const struct pam_conv conv = {
		.conv = pamconv,
		.appdata_ptr = NULL,
	};
	const char *ttydev;
	pid_t child;
	int ret;

	if (!user || !ruser)
		return 0;

	ret = pam_start(PAM_SERVICE_NAME, ruser, &conv, &pamh);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_start(\"%s\", \"%s\", ?, ?): failed",
		    PAM_SERVICE_NAME, ruser);

	ret = pam_set_item(pamh, PAM_RUSER, ruser);
	if (ret != PAM_SUCCESS)
		warn("pam_set_item(?, PAM_RUSER, \"%s\"): %s",
		    pam_strerror(pamh, ret), ruser);

	if (isatty(0) && (ttydev = ttyname(0)) != NULL) {
		if (strncmp(ttydev, "/dev/", 5) == 0)
			ttydev += 5;

		ret = pam_set_item(pamh, PAM_TTY, ttydev);
		if (ret != PAM_SUCCESS)
			warn("pam_set_item(?, PAM_TTY, \"%s\"): %s",
			    ttydev, pam_strerror(pamh, ret));
	}

	if (!nopass) {
		if (!interactive)
			errx(1, "Authorization required");

		/* doas style prompt for pam */
		char host[HOST_NAME_MAX + 1];
		if (gethostname(host, sizeof(host)))
			snprintf(host, sizeof(host), "?");
		snprintf(doas_prompt, sizeof(doas_prompt),
		    "\rdoas (%.32s@%.32s) password: ", ruser, host);

		/* authenticate */
		ret = pam_authenticate(pamh, 0);
		if (ret != PAM_SUCCESS) {
			pamcleanup(ret);
			return 0;
		}
	}

	ret = pam_acct_mgmt(pamh, 0);
	if (ret == PAM_NEW_AUTHTOK_REQD)
		ret = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);

	/* account not vaild or changing the auth token failed */
	if (ret != PAM_SUCCESS)
		return 0;

	/* set PAM_USER to the user we want to be */
	ret = pam_set_item(pamh, PAM_USER, user);
	if (ret != PAM_SUCCESS)
		warn("pam_set_item(?, PAM_USER, \"%s\"): %s", user,
		    pam_strerror(pamh, ret));

	ret = pam_setcred(pamh, PAM_ESTABLISH_CRED);
	if (ret != PAM_SUCCESS)
		warn("pam_setcred(?, PAM_ESTABLISH_CRED): %s", pam_strerror(pamh, ret));
	else
		cred_established = 1;

	/* open session */
	ret = pam_open_session(pamh, 0);
	if (ret != PAM_SUCCESS)
		errx(1, "pam_open_session: %s", pam_strerror(pamh, ret));
	else
		session_opened = 1;

	if ((child = fork()) == -1) {
		pamcleanup(PAM_ABORT);
		errx(1, "fork");
	}

	/* return as child */
	if (child == 0)
		return 1;

	watchsession(child);

	return 0;
}
