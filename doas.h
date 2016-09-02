/* $OpenBSD$ */
struct rule {
	int action;
	int options;
	const char *ident;
	const char *target;
	const char *cmd;
	const char **cmdargs;
	const char **envlist;
};

extern struct rule **rules;
extern int nrules, maxrules;
extern int parse_errors;

size_t arraylen(const char **);

char **prepenv(struct rule *);

#define PERMIT	1
#define DENY	2

#define NOPASS		0x1
#define KEEPENV		0x2
#define PERSIST		0x4
