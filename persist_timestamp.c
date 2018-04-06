/*
 * 1) Timestamp files and directories
 *
 * Timestamp files MUST NOT be accessible to users other than root,
 * this includes the name, metadata and the content of timestamp files
 * and directories.
 *
 * Symlinks can be used to create, manipulate or delete wrong files
 * and directories. The Implementation MUST reject any symlinks for
 * timestamp files or directories.
 *
 * To avoid race conditions the implementation MUST use the same
 * file descriptor for permission checks and do read or write
 * write operations after the permission checks.
 *
 * The timestamp files MUST be opened with openat(2) using the
 * timestamp directory file descriptor. Permissions of the directory
 * MUST be checked before opening the timestamp file descriptor.
 *
 * 2) Clock sources for timestamps
 *
 * Timestamp files MUST NOT rely on only one clock source, using the
 * wall clock would allow to reset the clock to an earlier point in
 * time to reuse a timestamp.
 *
 * The timestamp MUST consist of multiple clocks and MUST reject the
 * timestamp if there is a change to any clock because there is no way
 * to differentiate between malicious and legitimate clock changes.
 *
 * 3) Timestamp lifetime
 *
 * The implementation MUST NOT use the user controlled stdin, stdout
 * and stderr file descriptors to determine the controlling terminal.
 * On linux the /proc/$pid/stat file MUST be used to get the terminal
 * number.
 *
 * There is no reliable way to determine the lifetime of a tty/pty.
 * The start time of the session leader MUST be used as part of the
 * timestamp to determine if the tty is still the same.
 * If the start time of the session leader changed the timestamp MUST
 * be rejected.
 *
 */

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#if !defined(timespecisset) || \
    !defined(timespeccmp) || \
    !defined(timespecadd)
#	include "sys-time.h"
#endif

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "includes.h"

#ifndef TIMESTAMP_DIR
#	define TIMESTAMP_DIR "/tmp/doas"
#endif

#if defined(TIMESTAMP_TMPFS) && defined(__linux__)
#	ifndef TMPFS_MAGIC
#		define TMPFS_MAGIC 0x01021994
#	endif
#endif

#ifdef __linux__
/* Use tty_nr from /proc/self/stat instead of using
 * ttyname(3), stdin, stdout and stderr are user
 * controllable and would allow to reuse timestamps
 * from another writable terminal.
 * See https://www.sudo.ws/alerts/tty_tickets.html
 */
static int
proc_info(pid_t pid, int *ttynr, unsigned long long *starttime)
{
	char path[128];
	char buf[1024];
	char *p, *saveptr, *ep;
	const char *errstr;
	int fd, n;

	p = buf;

	if (snprintf(path, sizeof path, "/proc/%d/stat", pid) == -1)
		return -1;

	if ((fd = open(path, O_RDONLY)) == -1)
		return -1;

	while ((n = read(fd, p, buf + sizeof buf - p)) != 0) {
		if (n == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			break;
		}
		p += n;
		if (p >= buf + sizeof buf)
			break;
	}
	close(fd);

	/* error if it contains NULL bytes */
	if (n != 0 || memchr(buf, '\0', p - buf))
		return -1;

	/* Get the 7th field, 5 fields after the last ')',
	 * (2th field) because the 5th field 'comm' can include
	 * spaces and closing paranthesis too.
	 * See https://www.sudo.ws/alerts/linux_tty.html
	 */
	if ((p = strrchr(buf, ')')) == NULL)
		return -1;

	n = 2;
	for ((p = strtok_r(p, " ", &saveptr)); p;
	    (p = strtok_r(NULL, " ", &saveptr))) {
		switch (n++) {
		case 7:
			*ttynr = strtonum(p, INT_MIN, INT_MAX, &errstr);
			if (errstr)
				return -1;
			break;
		case 22:
			errno = 0;
			*starttime = strtoull(p, &ep, 10);
			if (p == ep ||
			   (errno == ERANGE && *starttime == ULLONG_MAX))
				return -1;
			break;
		}
		if (n == 23)
			break;
	}

	return 0;
}
#else
#error "proc_info not implemented"
#endif

static const char *
tsname()
{
	static char buf[128];
	int tty, fd;
	unsigned long long starttime;
	pid_t ppid, sid, leader;
	if ((fd = open("/dev/tty", O_RDONLY)) == -1)
		err(1, "open: /dev/tty");
	if (ioctl(fd, TIOCGSID, &leader) == -1)
		err(1, "ioctl: failed to get session leader");
	close(fd);
	if (proc_info(leader, &tty, &starttime) == -1)
		errx(1, "failed to get tty number");
	ppid = getppid();
	if ((sid = getsid(0)) == -1)
		err(1, "getsid");
	if (snprintf(buf, sizeof buf, ".%d_%d_%llu_%d_%d",
	    tty, leader, starttime, ppid, sid) == -1)
		return NULL;
	return buf;
}

static int
checktsdir(int fd)
{
	struct stat st;

	if (fstat(fd, &st) == -1)
		err(1, "fstatat");

	if ((st.st_mode & S_IFMT) != S_IFDIR)
		errx(0, "timestamp directory is not a directory");
	if ((st.st_mode & (S_IWGRP|S_IRGRP|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH)) != 0)
		errx(1, "timestamp directory permissions wrong");
	if (st.st_uid != 0 || st.st_gid != 0)
		errx(1, "timestamp directory is not owned by root");

#if defined(TIMESTAMP_TMPFS) && defined(__linux__)
	struct statfs sf;
	if (fstatfs(fd, &sf) == -1)
		err(1, "statfs");

	if (sf.f_type != TMPFS_MAGIC)
		errx(1, "timestamp directory not on tmpfs");
#endif

	return 0;
}

static int
opentsdir()
{
	gid_t gid;
	int fd;

reopen:
	if ((fd = open(TIMESTAMP_DIR, O_RDONLY | O_DIRECTORY)) == -1) {
		if (errno == ENOENT) {
			gid = getegid();
			if (setegid(0) != 0)
				err(1, "setegid");
			if (mkdir(TIMESTAMP_DIR, (S_IRUSR|S_IWUSR|S_IXUSR)) != 0)
				err(1, "mkdir");
			if (setegid(gid) != 0)
				err(1, "setegid");
			goto reopen;
		} else {
			err(1, "failed to open timestamp directory: %s", TIMESTAMP_DIR);
		}
	}

	if (checktsdir(fd) != 0)
		return -1;

	return fd;
}

static int
checktsfile(int fd, size_t *tssize)
{
	struct stat st;
	gid_t gid;

	if (fstat(fd, &st) == -1)
		err(1, "stat");
	if ((st.st_mode & S_IFMT) != S_IFREG)
		errx(1, "timestamp is not a regular file");
	if ((st.st_mode & (S_IWGRP|S_IRGRP|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH)) != 0)
		errx(1, "timestamp has wrong permissions");

	gid = getegid();
	if (st.st_uid != 0 || st.st_gid != gid)
		errx(1, "timestamp has wrong owner");

	*tssize = st.st_size;

	return 0;
}

static int
validts(int fd, int secs)
{
	struct timespec mono, real, ts_mono, ts_real, timeout;

	if (read(fd, &ts_mono, sizeof ts_mono) != sizeof ts_mono ||
	    read(fd, &ts_real, sizeof ts_real) != sizeof ts_real)
		err(1, "read");
	if (!timespecisset(&ts_mono) || !timespecisset(&ts_real))
		errx(1, "timespecisset");

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &mono) == -1 ||
	    clock_gettime(CLOCK_REALTIME, &real) == -1)
		err(1, "clock_gettime");

	if (timespeccmp(&mono, &ts_mono, >) ||
	    timespeccmp(&real, &ts_real, >))
		return -1;

	memset(&timeout, 0, sizeof timeout);
	timeout.tv_sec = secs;
	timespecadd(&timeout, &mono, &mono);
	timespecadd(&timeout, &real, &real);

	if (timespeccmp(&mono, &ts_mono, <) ||
	    timespeccmp(&real, &ts_real, <))
		errx(1, "timestamp is too far in the future");

	return 0;
}

int
persist_set(int fd, int secs)
{
	struct timespec mono, real, ts_mono, ts_real, timeout;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &mono) == -1 ||
	    clock_gettime(CLOCK_REALTIME, &real) == -1)
		err(1, "clock_gettime");

	memset(&timeout, 0, sizeof timeout);
	timeout.tv_sec = secs;
	timespecadd(&timeout, &mono, &ts_mono);
	timespecadd(&timeout, &real, &ts_real);

	if (lseek(fd, 0, SEEK_SET) == -1)
		err(1, "lseek");
	if (write(fd, (void *)&ts_mono, sizeof ts_mono) != sizeof ts_mono ||
	    write(fd, (void *)&ts_real, sizeof ts_real) != sizeof ts_real)
		err(1, "write");

	return 0;
}

int
persist_open(int *valid, int secs)
{
	int dirfd, fd;
	const char *name;

	*valid = 0;

	if ((name = tsname()) == NULL)
		errx(1, "failed to get timestamp name");
	if ((dirfd = opentsdir()) == -1)
		errx(1, "opentsdir");

	if ((fd = openat(dirfd, name, (O_RDWR), (S_IRUSR|S_IWUSR))) == -1)
		if (errno != ENOENT)
			err(1, "open timestamp file");

	if (fd == -1) {
		if ((fd = openat(dirfd, name, (O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW),
		    (S_IRUSR|S_IWUSR))) == -1)
			err(1, "open timestamp file");
	}

	size_t tssize;
	if (checktsfile(fd, &tssize) == -1)
		err(1, "checktsfile");

	/* The timestamp size is 0 if its a new file or a
	 * timestamp that was never set, its not valid but
	 * can be used to write the new timestamp.
	 * If the size does not match the expected size it
	 * is incomplete and should never be used
	 */
	if (tssize == sizeof(struct timespec) * 2)
		*valid = validts(fd, secs) == 0;
	else if (tssize != 0)
		errx(1, "corrupt timestamp file");

	close(dirfd);
	return fd;
}

int
persist_clear()
{
	const char *name;
	int dirfd;
	if ((name = tsname()) == NULL)
		errx(1, "failed to get timestamp name");
	if ((dirfd = opentsdir()) == -1)
		errx(1, "opentsdir");
	if (unlinkat(dirfd, name, 0) == -1 && errno != ENOENT)
		return -1;
	close(dirfd);
	return 0;
}
