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

#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include "openbsd.h"

int
setusercontext(login_cap_t *lc, struct passwd *pw, uid_t uid, unsigned int flags)
{
	int ret;

	if (lc != NULL || pw == NULL ||
			(flags & ~(LOGIN_SETGROUP | LOGIN_SETPRIORITY |
			           LOGIN_SETRESOURCES | LOGIN_SETUMASK |
			           LOGIN_SETUSER)) != 0) {
		errno = EINVAL;
		return -1;
	}

	if (flags & LOGIN_SETGROUP) {
		if ((ret = setgid(pw->pw_gid)) != 0)
			return ret;
		if ((ret = initgroups(pw->pw_name, pw->pw_gid)) != 0)
			return ret;
	}

	if (flags & LOGIN_SETPRIORITY) {
		if ((ret = setpriority(PRIO_PROCESS, getpid(), 0)) != 0)
			return ret;
		if ((ret = setpriority(PRIO_USER, uid, 0)) != 0)
			return ret;
	}

	if (flags & LOGIN_SETRESOURCES) {
	}

	if (flags & LOGIN_SETUMASK)
		umask(S_IWGRP | S_IWOTH);

	if (flags & LOGIN_SETUSER)
		return setuid(uid);

	return 0;
}

