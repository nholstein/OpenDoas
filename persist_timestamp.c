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

#include <sys/stat.h>
#include <sys/vfs.h>

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

static char *
tspath()
{
	char *path, *tty, *ttynorm, *p;
	if (!(tty = ttyname(0))
	    && !(tty = ttyname(1))
		&& !(tty = ttyname(2)))
		err(1, "ttyname");
	if (!(ttynorm = strdup(tty)))
		err(1, "strdup");
	for (p = ttynorm; *p; p++)
		if (!isalnum(*p))
			*p = '_';
	if (asprintf(&path, "%s/.%s_%d", TIMESTAMP_DIR, ttynorm, getppid()) == -1)
		errx(1, "asprintf");
	free(ttynorm);
	return path;
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
	if ((st.st_mode & (S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH)) != 0)
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

static int
timestamp_read(int fd, struct timespec *mono, struct timespec *real)
{
	if (read(fd, (void *)mono, sizeof *mono) != sizeof *mono ||
	    read(fd, (void *)real, sizeof *real) != sizeof *mono)
		err(1, "read");
	if (!timespecisset(mono) || !timespecisset(real))
		errx(1, "timespecisset");
	return 0;
}

int
persist_check(int fd, int secs)
{
	struct timespec mono, real, ts_mono, ts_real, timeout;

	if (timestamp_read(fd, &ts_mono, &ts_real) != 0)
		return 1;

	if (clock_gettime(CLOCK_MONOTONIC, &mono) != 0 || !timespecisset(&mono))
		err(1, "clock_gettime(CLOCK_MONOTONIC, ?)");
	if (clock_gettime(CLOCK_REALTIME, &real) != 0 || !timespecisset(&real))
		err(1, "clock_gettime(CLOCK_REALTIME, ?)");

	if (timespeccmp(&mono, &ts_mono, >) ||
	    timespeccmp(&real, &ts_real, >))
		return 1;

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

	if (clock_gettime(CLOCK_MONOTONIC, &mono) != 0 || !timespecisset(&mono))
		err(1, "clock_gettime(XLOCK_MONOTONIC, ?)");
	if (clock_gettime(CLOCK_REALTIME, &real) != 0 || !timespecisset(&real))
		err(1, "clock_gettime(CLOCK_REALTIME, ?)");

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

	path = tspath();
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
	path = tspath();
	if (unlink(path) == -1 && errno != ENOENT)
		return -1;
	return 0;
}
