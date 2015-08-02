/* Copyright 2015 Nathan Holstein */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "openbsd.h"

int
auth_userokay(char *name, char *style, char *type, char *password)
{
	if (style || type || password) {
		fprintf(stderr, "auth_userokay(name, NULL, NULL, NULL)!\n");
		exit(1);
	}

	fprintf(stderr, "failing auth check for %s\n", name);

	return 0;
}

