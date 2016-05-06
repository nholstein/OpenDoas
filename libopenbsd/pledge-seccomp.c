/*	$OpenBSD: kern_pledge.c,v 1.165 2016/04/28 14:25:08 beck Exp $	*/

/*
 * Copyright (c) 2015 Nicholas Marriott <nicm@openbsd.org>
 * Copyright (c) 2015 Theo de Raadt <deraadt@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <seccomp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <err.h>

#include "openbsd.h"
#include "pledge.h"

#define SYS_MAXSYSCALL 1000

/*
 * Ordered in blocks starting with least risky and most required.
 */
const uint64_t pledge_syscalls[SYS_MAXSYSCALL] = {
	/*
	 * Minimum required
	 */
	[SYS_exit] = PLEDGE_ALWAYS,
	// [SYS_kbind] = PLEDGE_ALWAYS,
	// [SYS___get_tcb] = PLEDGE_ALWAYS,
	// [SYS_pledge] = PLEDGE_ALWAYS,
	// [SYS_sendsyslog] = PLEDGE_ALWAYS,	/* stack protector reporting */
	// [SYS_osendsyslog] = PLEDGE_ALWAYS,	/* obsolete sendsyslog */
	// [SYS_thrkill] = PLEDGE_ALWAYS,		/* raise, abort, stack pro */
	// [SYS_utrace] = PLEDGE_ALWAYS,		/* ltrace(1) from ld.so */

	/* "getting" information about self is considered safe */
	[SYS_getuid] = PLEDGE_STDIO,
	[SYS_geteuid] = PLEDGE_STDIO,
	[SYS_getresuid] = PLEDGE_STDIO,
	[SYS_getgid] = PLEDGE_STDIO,
	[SYS_getegid] = PLEDGE_STDIO,
	[SYS_getresgid] = PLEDGE_STDIO,
	[SYS_getgroups] = PLEDGE_STDIO,
	// [SYS_getlogin59] = PLEDGE_STDIO,
	// [SYS_getlogin_r] = PLEDGE_STDIO,
	[SYS_getpgrp] = PLEDGE_STDIO,
	[SYS_getpgid] = PLEDGE_STDIO,
	[SYS_getppid] = PLEDGE_STDIO,
	[SYS_getsid] = PLEDGE_STDIO,
	// [SYS_getthrid] = PLEDGE_STDIO,
	[SYS_getrlimit] = PLEDGE_STDIO,
	[SYS_gettimeofday] = PLEDGE_STDIO,
	// [SYS_getdtablecount] = PLEDGE_STDIO,
	[SYS_getrusage] = PLEDGE_STDIO,
	// [SYS_issetugid] = PLEDGE_STDIO,
	[SYS_clock_getres] = PLEDGE_STDIO,
	[SYS_clock_gettime] = PLEDGE_STDIO,
	[SYS_getpid] = PLEDGE_STDIO,

	/*
	 * Almost exclusively read-only, Very narrow subset.
	 * Use of "route", "inet", "dns", "ps", or "vminfo"
	 * expands access.
	 */
	// [SYS_sysctl] = PLEDGE_STDIO,

	/* Support for malloc(3) family of operations */
	// [SYS_getentropy] = PLEDGE_STDIO,
	[SYS_madvise] = PLEDGE_STDIO,
	// [SYS_minherit] = PLEDGE_STDIO,
	[SYS_mmap] = PLEDGE_STDIO,
	[SYS_mprotect] = PLEDGE_STDIO,
	// [SYS_mquery] = PLEDGE_STDIO,
	[SYS_munmap] = PLEDGE_STDIO,
	[SYS_msync] = PLEDGE_STDIO,
	// [SYS_break] = PLEDGE_STDIO,

	[SYS_umask] = PLEDGE_STDIO,

	/* read/write operations */
	[SYS_read] = PLEDGE_STDIO,
	[SYS_readv] = PLEDGE_STDIO,
	// [SYS_pread] = PLEDGE_STDIO,
	[SYS_preadv] = PLEDGE_STDIO,
	[SYS_write] = PLEDGE_STDIO,
	[SYS_writev] = PLEDGE_STDIO,
	// [SYS_pwrite] = PLEDGE_STDIO,
	[SYS_pwritev] = PLEDGE_STDIO,
	[SYS_recvmsg] = PLEDGE_STDIO,
	[SYS_recvfrom] = PLEDGE_STDIO | PLEDGE_YPACTIVE,
	[SYS_ftruncate] = PLEDGE_STDIO,
	[SYS_lseek] = PLEDGE_STDIO,
	// [SYS_fpathconf] = PLEDGE_STDIO,

	/*
	 * Address selection required a network pledge ("inet",
	 * "unix", "dns".
	 */
	[SYS_sendto] = PLEDGE_STDIO | PLEDGE_YPACTIVE,

	/*
	 * Address specification required a network pledge ("inet",
	 * "unix", "dns".  SCM_RIGHTS requires "sendfd" or "recvfd".
	 */
	[SYS_sendmsg] = PLEDGE_STDIO,

	/* Common signal operations */
	[SYS_nanosleep] = PLEDGE_STDIO,
	[SYS_sigaltstack] = PLEDGE_STDIO,
	// [SYS_sigprocmask] = PLEDGE_STDIO,
	// [SYS_sigsuspend] = PLEDGE_STDIO,
	// [SYS_sigaction] = PLEDGE_STDIO,
	// [SYS_sigreturn] = PLEDGE_STDIO,
	// [SYS_sigpending] = PLEDGE_STDIO,
	[SYS_getitimer] = PLEDGE_STDIO,
	[SYS_setitimer] = PLEDGE_STDIO,

	/*
	 * To support event driven programming.
	 */
	[SYS_poll] = PLEDGE_STDIO,
	[SYS_ppoll] = PLEDGE_STDIO,
	// [SYS_kevent] = PLEDGE_STDIO,
	// [SYS_kqueue] = PLEDGE_STDIO,
	[SYS_select] = PLEDGE_STDIO,
	// [SYS_pselect] = PLEDGE_STDIO,
	[SYS_pselect6] = PLEDGE_STDIO,
	[SYS_epoll_create] = PLEDGE_STDIO,
	[SYS_epoll_create1] = PLEDGE_STDIO,
	[SYS_epoll_ctl] = PLEDGE_STDIO,
	[SYS_epoll_pwait] = PLEDGE_STDIO,
	[SYS_epoll_wait] = PLEDGE_STDIO,
	[SYS_eventfd] = PLEDGE_STDIO,
	[SYS_eventfd2] = PLEDGE_STDIO,

	[SYS_fstat] = PLEDGE_STDIO,
	[SYS_fsync] = PLEDGE_STDIO,

	[SYS_setsockopt] = PLEDGE_STDIO,	/* narrow whitelist */
	[SYS_getsockopt] = PLEDGE_STDIO,	/* narrow whitelist */

	/* F_SETOWN requires PLEDGE_PROC */
	[SYS_fcntl] = PLEDGE_STDIO,

	[SYS_close] = PLEDGE_STDIO,
	[SYS_dup] = PLEDGE_STDIO,
	[SYS_dup2] = PLEDGE_STDIO,
	[SYS_dup3] = PLEDGE_STDIO,
	// [SYS_closefrom] = PLEDGE_STDIO,
	[SYS_shutdown] = PLEDGE_STDIO,
	[SYS_fchdir] = PLEDGE_STDIO,	/* XXX consider tightening */

	[SYS_pipe] = PLEDGE_STDIO,
	[SYS_pipe2] = PLEDGE_STDIO,
	[SYS_socketpair] = PLEDGE_STDIO,

	[SYS_wait4] = PLEDGE_STDIO,

	/*
	 * Can kill self with "stdio".  Killing another pid
	 * requires "proc"
	 */
	// [SYS_o58_kill] = PLEDGE_STDIO,
	[SYS_kill] = PLEDGE_STDIO,

	/*
	 * FIONREAD/FIONBIO for "stdio"
	 * A few non-tty ioctl available using "ioctl"
	 * tty-centric ioctl available using "tty"
	 */
	[SYS_ioctl] = PLEDGE_STDIO,

	/*
	 * Path access/creation calls encounter many extensive
	 * checks are done during namei()
	 */
	[SYS_open] = PLEDGE_STDIO,
	[SYS_stat] = PLEDGE_STDIO,
	[SYS_access] = PLEDGE_STDIO,
	[SYS_readlink] = PLEDGE_STDIO,

	// [SYS_adjtime] = PLEDGE_STDIO,   /* setting requires "settime" */
	// [SYS_adjfreq] = PLEDGE_SETTIME,
	[SYS_settimeofday] = PLEDGE_SETTIME,

	/*
	 * Needed by threaded programs
	 * XXX should we have a new "threads"?
	 */
	// [SYS___tfork] = PLEDGE_STDIO,
	[SYS_sched_yield] = PLEDGE_STDIO,
	// [SYS___thrsleep] = PLEDGE_STDIO,
	// [SYS___thrwakeup] = PLEDGE_STDIO,
	// [SYS___threxit] = PLEDGE_STDIO,
	// [SYS___thrsigdivert] = PLEDGE_STDIO,

	[SYS_fork] = PLEDGE_PROC,
	[SYS_vfork] = PLEDGE_PROC,
	[SYS_setpgid] = PLEDGE_PROC,
	[SYS_setsid] = PLEDGE_PROC,

	[SYS_setrlimit] = PLEDGE_PROC | PLEDGE_ID,
	[SYS_getpriority] = PLEDGE_PROC | PLEDGE_ID,

	[SYS_setpriority] = PLEDGE_PROC | PLEDGE_ID,

	[SYS_setuid] = PLEDGE_ID,
	// [SYS_seteuid] = PLEDGE_ID,
	[SYS_setreuid] = PLEDGE_ID,
	[SYS_setresuid] = PLEDGE_ID,
	[SYS_setgid] = PLEDGE_ID,
	// [SYS_setegid] = PLEDGE_ID,
	[SYS_setregid] = PLEDGE_ID,
	[SYS_setresgid] = PLEDGE_ID,
	[SYS_setgroups] = PLEDGE_ID,
	// [SYS_setlogin] = PLEDGE_ID,

	[SYS_execve] = PLEDGE_EXEC,

	[SYS_chdir] = PLEDGE_RPATH,
	[SYS_openat] = PLEDGE_RPATH | PLEDGE_WPATH,
	// [SYS_fstatat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_newfstatat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_faccessat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_readlinkat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_lstat] = PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_TMPPATH,
	[SYS_truncate] = PLEDGE_WPATH,
	[SYS_rename] = PLEDGE_CPATH,
	[SYS_rmdir] = PLEDGE_CPATH,
	[SYS_renameat] = PLEDGE_CPATH,
	[SYS_link] = PLEDGE_CPATH,
	[SYS_linkat] = PLEDGE_CPATH,
	[SYS_symlink] = PLEDGE_CPATH,
	[SYS_unlink] = PLEDGE_CPATH | PLEDGE_TMPPATH,
	[SYS_unlinkat] = PLEDGE_CPATH,
	[SYS_mkdir] = PLEDGE_CPATH,
	[SYS_mkdirat] = PLEDGE_CPATH,

	// [SYS_mkfifo] = PLEDGE_DPATH,
	[SYS_mknod] = PLEDGE_DPATH,

	[SYS_chroot] = PLEDGE_ID,	/* also requires PLEDGE_PROC */

	// [SYS_revoke] = PLEDGE_TTY,	/* also requires PLEDGE_RPATH */

	/*
	 * Classify as RPATH|WPATH, because of path information leakage.
	 * WPATH due to unknown use of mk*temp(3) on non-/tmp paths..
	 */
	// [SYS___getcwd] = PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_getcwd] = PLEDGE_RPATH | PLEDGE_WPATH,

	/* Classify as RPATH, because these leak path information */
	[SYS_getdents] = PLEDGE_RPATH,
	// [SYS_getfsstat] = PLEDGE_RPATH,
	[SYS_statfs] = PLEDGE_RPATH,
	[SYS_fstatfs] = PLEDGE_RPATH,
	// [SYS_pathconf] = PLEDGE_RPATH,

	[SYS_utimes] = PLEDGE_FATTR,
	// [SYS_futimes] = PLEDGE_FATTR,
	[SYS_futimesat] = PLEDGE_FATTR,
	[SYS_utimensat] = PLEDGE_FATTR,
	// [SYS_futimens] = PLEDGE_FATTR,
	[SYS_chmod] = PLEDGE_FATTR,
	[SYS_fchmod] = PLEDGE_FATTR,
	[SYS_fchmodat] = PLEDGE_FATTR,
	// [SYS_chflags] = PLEDGE_FATTR,
	//[SYS_chflagsat] = PLEDGE_FATTR,
	// [SYS_fchflags] = PLEDGE_FATTR,
	[SYS_chown] = PLEDGE_FATTR,
	[SYS_fchownat] = PLEDGE_FATTR,
	[SYS_lchown] = PLEDGE_FATTR,
	[SYS_fchown] = PLEDGE_FATTR,

	[SYS_socket] = PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS | PLEDGE_YPACTIVE,
	[SYS_connect] = PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS | PLEDGE_YPACTIVE,
	[SYS_bind] = PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS | PLEDGE_YPACTIVE,
	[SYS_getsockname] = PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS | PLEDGE_YPACTIVE,

	[SYS_listen] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_accept4] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_accept] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_getpeername] = PLEDGE_INET | PLEDGE_UNIX,

	[SYS_flock] = PLEDGE_FLOCK | PLEDGE_YPACTIVE,

	// [SYS_swapctl] = PLEDGE_VMINFO,	/* XXX should limit to "get" operations */
};


static const struct {
	char *name;
	int flags;
} pledgereq[] = {
	{ "audio",		PLEDGE_AUDIO },
	{ "cpath",		PLEDGE_CPATH },
	{ "disklabel",		PLEDGE_DISKLABEL },
	{ "dns",		PLEDGE_DNS },
	{ "dpath",		PLEDGE_DPATH },
	{ "drm",		PLEDGE_DRM },
	{ "exec",		PLEDGE_EXEC },
	{ "fattr",		PLEDGE_FATTR },
	{ "flock",		PLEDGE_FLOCK },
	{ "getpw",		PLEDGE_GETPW },
	{ "id",			PLEDGE_ID },
	{ "inet",		PLEDGE_INET },
	{ "ioctl",		PLEDGE_IOCTL },
	{ "mcast",		PLEDGE_MCAST },
	{ "pf",			PLEDGE_PF },
	{ "proc",		PLEDGE_PROC },
	{ "prot_exec",		PLEDGE_PROTEXEC },
	{ "ps",			PLEDGE_PS },
	{ "recvfd",		PLEDGE_RECVFD },
	{ "route",		PLEDGE_ROUTE },
	{ "rpath",		PLEDGE_RPATH },
	{ "sendfd",		PLEDGE_SENDFD },
	{ "settime",		PLEDGE_SETTIME },
	{ "stdio",		PLEDGE_STDIO },
	{ "tmppath",		PLEDGE_TMPPATH },
	{ "tty",		PLEDGE_TTY },
	{ "unix",		PLEDGE_UNIX },
	{ "vminfo",		PLEDGE_VMINFO },
	{ "vmm",		PLEDGE_VMM },
	{ "wpath",		PLEDGE_WPATH },
};

scmp_filter_ctx scmp_ctx = NULL;

/* bsearch over pledgereq. return flags value if found, 0 else */
static int
pledgereq_flags(const char *req_name)
{
	int base = 0, cmp, i, lim;

	for (lim = nitems(pledgereq); lim != 0; lim >>= 1) {
		i = base + (lim >> 1);
		cmp = strcmp(req_name, pledgereq[i].name);
		if (cmp == 0)
			return (pledgereq[i].flags);
		if (cmp > 0) { /* not found before, move right */
			base = i + 1;
			lim--;
		} /* else move left */
	}
	return (0);
}

/* whitelists syscalls returns -1 on error */
int
pledge(const char *promises, __UNUSED const char *paths[])
{
	char *buf, *p;
	int rv = 0;
	uint64_t flags = 0;

	if (scmp_ctx == NULL) {
		/* inintialize new seccomp whitelist */
		if ((scmp_ctx = seccomp_init(SCMP_ACT_KILL)) == NULL)
			err(1, "seccomp_init");
	} else {
		/* reset previous rules */
		if (seccomp_reset(scmp_ctx, SCMP_ACT_KILL) < 0)
			err(1, "seccomp_reset");
	}

	/* make flags from prmises string */
	buf = strdup(promises);
	for (p = strtok(buf, " "); p;
			 p = strtok(NULL, " ")) {
		flags |= pledgereq_flags(p);
	}

	for (int i = 0; i < SYS_MAXSYSCALL; i++) {
		/* skip not defined syscalls */
		if (pledge_syscalls[i] == 0)
			continue;

		/* skip not matching syscalls */
		if (!(pledge_syscalls[i] & flags))
			continue;

		/* seccomp whitelist syscall */
		if((rv = seccomp_rule_add_exact(scmp_ctx, SCMP_ACT_ALLOW, i, 0)) != 0)
			goto out;
	}

	/* seccomp_export_pfc(scmp_ctx, STDERR_FILENO); */

out:
	free(buf);
	free(p);

	/* seccomp_release(scmp_ctx); */

	return (rv == 0 ? 0 : -1);
}
