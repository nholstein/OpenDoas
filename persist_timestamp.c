#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/vfs.h>

#include "includes.h"

#ifndef TIMESTAMP_DIR
# define TIMESTAMP_DIR "/tmp/doas"
#endif
#ifndef TMPFS_MAGIC
# define TMPFS_MAGIC 0x01021994
#endif

#define	timespecisset(tsp)		((tsp)->tv_sec || (tsp)->tv_nsec)
#define	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :		\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#define	timespecadd(tsp, usp, vsp) do {						\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec >= 1000000000L) {				\
			(vsp)->tv_sec++;								\
			(vsp)->tv_nsec -= 1000000000L;					\
		}													\
	} while (0)


#ifdef __linux__
/* Use tty_nr from /proc/self/stat instead of using
 * ttyname(3), stdin, stdout and stderr are user
 * controllable and would allow to reuse timestamps
 * from another writable terminal.
 * See https://www.sudo.ws/alerts/tty_tickets.html
 */
static int
ttynr()
{
	char buf[1024];
	char *p, *p1, *saveptr;
	const char *errstr;
	int fd, n;

	p = buf;

	if ((fd = open("/proc/self/stat", O_RDONLY)) == -1)
		return -1;

	while ((n = read(fd, p, buf + sizeof buf - p)) != 0) {
		if (n == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			else
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
	 * because the 5th field 'comm' can include spaces
	 * and closing paranthesis too.
	 * See https://www.sudo.ws/alerts/linux_tty.html
	 */
	if ((p = strrchr(buf, ')')) == NULL)
		return -1;
	for ((p1 = strtok_r(p, " ", &saveptr)), n = 0; p1;
	    (p1 = strtok_r(NULL, " ", &saveptr)), n++)
		if (n == 5)
			break;
	if (p1 == NULL || n != 5)
		return -1;

	n = strtonum(p1, INT_MIN, INT_MAX, &errstr);
	if (errstr)
		return -1;

	return n;
}
#else
#error "ttynr not implemented"
#endif

static char pathbuf[PATH_MAX];

static int
tspath(const char **path)
{
	int tty;
	pid_t ppid;
	if (*pathbuf == '\0') {
		if ((tty = ttynr()) == -1)
			errx(1, "failed to get tty number");
		ppid = getppid();
		if (snprintf(pathbuf, sizeof pathbuf, "%s/.%d_%d",
		    TIMESTAMP_DIR, tty, ppid) == -1)
			return -1;
	}
	*path = pathbuf;
	return 0;
}

static int
checktsdir(const char *path)
{
	char *dir, *buf;
	struct stat st;
	struct statfs sf;
	gid_t gid;

	if (!(buf = strdup(path)))
		err(1, "strdup");
	dir = dirname(buf);

check:
	if (lstat(dir, &st) == -1) {
		if (errno == ENOENT) {
			gid = getegid();
			if (setegid(0) != 0)
				err(1, "setegid");
			if (mkdir(dir, (S_IRUSR|S_IWUSR|S_IXUSR)) != 0)
				err(1, "mkdir");
			if (setegid(gid) != 0)
				err(1, "setegid");
			goto check;
		} else {
			err(1, "stat");
		}
	}

	if ((st.st_mode & S_IFMT) != S_IFDIR)
		errx(1, "timestamp directory is not a directory");
	if ((st.st_mode & (S_IWGRP|S_IRGRP|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH)) != 0)
		errx(1, "timestamp directory permissions wrong");
	if (st.st_uid != 0 || st.st_gid != 0)
		errx(1, "timestamp directory is not owned by root");
	if (statfs(dir, &sf) == -1)
		err(1, "statfs");
	if (sf.f_type != TMPFS_MAGIC)
		errx(1, "timestamp directory not on tmpfs");

	free(buf);
	return 0;
}

int
persist_check(int fd, int secs)
{
	struct timespec mono, real, ts_mono, ts_real, timeout;

	if (read(fd, &ts_mono, sizeof ts_mono) != sizeof ts_mono ||
	    read(fd, &ts_real, sizeof ts_real) != sizeof ts_mono)
		err(1, "read");
	if (!timespecisset(&ts_mono) || !timespecisset(&ts_real))
		errx(1, "timespecisset");

	if (clock_gettime(CLOCK_MONOTONIC, &mono) == -1 ||
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

	if (clock_gettime(CLOCK_MONOTONIC, &mono) == -1 ||
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
	struct stat st;
	int fd;
	gid_t gid;
	const char *path;

	if (tspath(&path) == -1)
		errx(1, "failed to get timestamp path");
	if (checktsdir(path))
		errx(1, "checktsdir");

	if ((fd = open(path, (O_RDWR), (S_IRUSR|S_IWUSR))) == -1)
		if (errno != ENOENT)
			err(1, "open: %s", path);

	if (fd == -1) {
		if ((fd = open(path, (O_RDWR|O_CREAT|O_EXCL), (S_IRUSR|S_IWUSR))) == -1)
			err(1, "open: %s", path);
		*valid = 0;
		return fd;
	}

	if (fstat(fd, &st) == -1)
		err(1, "stat");
	if ((st.st_mode & S_IFMT) != S_IFREG)
		errx(1, "timestamp is not a file");
	if ((st.st_mode & (S_IWGRP|S_IRGRP|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH)) != 0)
		errx(1, "timestamp permissions wrong");

	gid = getegid();
	if (st.st_uid != 0 || st.st_gid != gid)
		errx(1, "timestamp has wrong owner");

	if (st.st_size == 0) {
		*valid = 0;
		return fd;
	}

	if (st.st_size != sizeof(struct timespec) * 2)
		errx(1, "corrupt timestamp file");

	*valid = persist_check(fd, secs) == 0;

	return fd;
}

int
persist_clear()
{
	const char *path;
	if (tspath(&path) == -1)
		errx(1, "failed to get timestamp path");
	if (unlink(path) == -1 && errno != ENOENT)
		return -1;
	return 0;
}
