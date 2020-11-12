#ifndef INCLUDES_H
#define INCLUDES_H

#include "openbsd.h"

#ifdef USE_PAM
void pamauth(const char *, const char *, int, int, int);
#endif

#ifdef USE_SHADOW
void shadowauth(const char *, int);
#endif

#ifdef USE_TIMESTAMP
int timestamp_open(int *, int);
int timestamp_set(int, int);
int timestamp_clear(void);
#endif

#endif /* INCLUDES_H */
