/* Copyright 2015 Nathan Holstein */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "openbsd.h"

int
setusercontext(login_cap_t *lc, struct passwd *pwd, uid_t uid, unsigned int flags)
{
	if (lc != NULL || pwd == NULL ||
			(flags & ~(LOGIN_SETGROUP | LOGIN_SETPRIORITY |
			           LOGIN_SETRESOURCES | LOGIN_SETUMASK |
			           LOGIN_SETUSER)) != 0) {
		errno = EINVAL;
		return -1;
	}

	fprintf(stderr, "failing setusercontext() for %d\n", (int) uid);

	return -1;
}

