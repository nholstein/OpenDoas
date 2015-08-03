#ifndef _LIB_OPENBSD_H_
#define _LIB_OPENBSD_H_

#include <sys/types.h>

/* API definitions lifted from OpenBSD src/include */

/* bsd_auth.h */
int auth_userokay(char *, char *, char *, char *);

/* login_cap.h */
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

/* pwd.h */
#define _PW_NAME_LEN 63

/* stdlib.h */
void * reallocarray(void *optr, size_t nmemb, size_t size);
long long strtonum(const char *numstr, long long minval,
		long long maxval, const char **errstrp);

/* string.h */
void explicit_bzero(void *, size_t);

/* unistd.h */
int execvpe(const char *, char *const *, char *const *);
int setresuid(uid_t, uid_t, uid_t);

#endif
