/* Copyright 2015 Nathan Holstein */

#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

/* I don't think we can actually mimic the right semantics? */
int
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	int ret;
	if (suid != ruid) {
		errno = EPERM;
		return -1;
	}
	if ((ret = setuid(ruid)) != 0)
		return ret;
	if ((ret = seteuid(euid)) != 0)
		return ret;
	return 0;
}

