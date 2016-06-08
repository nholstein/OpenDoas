#ifndef INCLUDES_H
#define INCLUDES_H

#ifndef __UNUSED
# define __UNUSED __attribute__ ((unused))
#endif

#ifndef __dead
# define __dead
#endif

#ifndef _PATH_TTY
# define _PATH_TTY "/dev/tty"
#endif

#ifdef HAVE_READPASSPHRASE_H
# include <readpassphrase.h>
#endif

#include "openbsd.h"

#ifdef HAVE_PAM_APPL_H
int doas_pam(const char *user, const char *ruser, int interactive, int nopass);
#endif

#endif /* INCLUDES_H */
