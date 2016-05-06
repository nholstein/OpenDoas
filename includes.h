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

#endif /* INCLUDES_H */
