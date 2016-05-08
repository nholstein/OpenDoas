#ifndef _LIB_OPENBSD_H_
#define _LIB_OPENBSD_H_

#include <stdarg.h>
#include <sys/types.h>
#include <sys/cdefs.h>

#include "readpassphrase.h"

/* API definitions lifted from OpenBSD src/include */

/* login_cap.h */
#ifndef HAVE_LOGIN_CAP_H
#define        LOGIN_SETGROUP          0x0001  /* Set group */
#define        LOGIN_SETLOGIN          0x0002  /* Set login */
#define        LOGIN_SETPATH           0x0004  /* Set path */
#define        LOGIN_SETPRIORITY       0x0008  /* Set priority */
#define        LOGIN_SETRESOURCES      0x0010  /* Set resource limits */
#define        LOGIN_SETUMASK          0x0020  /* Set umask */
#define        LOGIN_SETUSER           0x0040  /* Set user */
#define        LOGIN_SETENV            0x0080  /* Set environment */
#define        LOGIN_SETALL            0x00ff  /* Set all. */

typedef struct login_cap login_cap_t;
struct passwd;
int setusercontext(login_cap_t *, struct passwd *, uid_t, unsigned int);
#endif /* !HAVE_LOGIN_CAP_H */

/* pwd.h */
#define _PW_NAME_LEN 63

/* stdlib.h */
#ifndef HAVE_REALLOCARRAY
void * reallocarray(void *optr, size_t nmemb, size_t size);
#endif /* HAVE_REALLOCARRAY */
#ifndef HAVE_STRTONUM
long long strtonum(const char *numstr, long long minval,
		long long maxval, const char **errstrp);
#endif /* !HAVE_STRTONUM */

/* string.h */
#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *, size_t);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t dsize);
#endif /* !HAVE_STRLCAT */
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t dsize);
#endif /* !HAVE_STRLCPY */

/* unistd.h */
#ifndef HAVE_EXECVPE
int execvpe(const char *, char *const *, char *const *);
#endif /* !HAVE_EXECVPE */
#ifndef HAVE_SETRESUID
int setresuid(uid_t, uid_t, uid_t);
#endif /* !HAVE_SETRESUID */
#ifndef HAVE_PLEDGE
int pledge(const char *promises, const char *paths[]);
#endif /* !HAVE_PLEDGE */

/* err.h */
#ifndef HAVE_VERRC
void verrc(int eval, int code, const char *fmt, va_list ap);
#endif /* !HAVE_VERRC */
#ifndef HAVE_ERRC
void errc(int eval, int code, const char *fmt, ...);
#endif /* !HAVE_ERRC */

#ifndef HAVE_SETPROGNAME
const char * getprogname(void);
void setprogname(const char *progname);
#endif /* !HAVE_SETPROGNAME */

#endif /* _LIB_OPENBSD_H_ */
