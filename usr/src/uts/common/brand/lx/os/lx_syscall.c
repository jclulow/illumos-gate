/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/proc.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/model.h>
#include <sys/privregs.h>
#include <sys/brand.h>
#include <sys/machbrand.h>
#include <sys/sdt.h>
#include <sys/lx_syscalls.h>
#include <sys/lx_brand.h>
#include <sys/lx_impl.h>
#include <sys/lx_misc.h>


/*
 * Flags for sysent entries:
 */
#define	LX_SYS_NOSYS_REASON	0x07
#define	LX_SYS_EBPARG6		0x08

/*
 * Flags that denote the specific reason we do not have a particular system
 * call.  These reasons are only valid if the function is NULL.
 */
#define	NOSYS_USERMODE		0
#define	NOSYS_NULL		1
#define	NOSYS_NONE		2
#define	NOSYS_NO_EQUIV		3
#define	NOSYS_KERNEL		4
#define	NOSYS_UNDOC		5
#define	NOSYS_OBSOLETE		6
#define	NOSYS_MAX		NOSYS_OBSOLETE

#if NOSYS_MAX > LX_SYS_NOSYS_REASON
#error NOSYS reason codes must fit in LX_SYS_NOSYS_REASON
#endif

/*
 * Strings describing the reason we do not emulate a particular system call
 * in the kernel.
 */
static char *nosys_reasons[] = {
	NULL, /* NOSYS_USERMODE means this call is emulated in usermode */
	"Not done yet",
	"No such Linux system call",
	"No equivalent illumos functionality",
	"Reads/modifies Linux kernel state",
	"Undocumented and/or rarely used system call",
	"Unsupported, obsolete system call"
};


#if defined(_LP64)
/*
 * System call handler table and entry count for Linux x86_64 (amd64):
 */
lx_sysent_t lx_sysent64[LX_NSYSCALLS + 1];
int lx_nsysent64;
#endif
/*
 * System call handler table and entry count for Linux x86 (i386):
 */
lx_sysent_t lx_sysent32[LX_NSYSCALLS + 1];
int lx_nsysent32;

/*
 * Map Illumos errno to the Linux equivalent.
 */
int lx_stol_errno[] = LX_STOL_ERRNO_INIT;

#if defined(__amd64)
static int
lx_emulate_args(klwp_t *lwp, const lx_sysent_t *s, uintptr_t *args)
{
	struct regs *rp = lwptoregs(lwp);

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		/*
		 * Note: Syscall argument passing is different from function
		 * call argument passing on amd64.  For function calls, the
		 * fourth arg is passed via %rcx, but for system calls the 4th
		 * arg is passed via %r10.  This is because in amd64, the
		 * syscall instruction puts the lower 32 bits of %rflags in
		 * %r11 and puts the %rip value to %rcx.
		 *
		 * Appendix A of the amd64 ABI (Linux conventions) states that
		 * syscalls are limited to 6 args and no arg is passed on the
		 * stack.
		 */
		args[0] = rp->r_rdi;
		args[1] = rp->r_rsi;
		args[2] = rp->r_rdx;
		args[3] = rp->r_r10;
		args[4] = rp->r_r8;
		args[5] = rp->r_r9;
	} else {
		/*
		 * If the system call takes 6 args, then libc has stashed them
		 * in memory at the address contained in %ebx. Except for some
		 * syscalls which store the 6th argument in %ebp.
		 */
		if (s->sy_narg == 6 && !(s->sy_flags & LX_SYS_EBPARG6)) {
			uint32_t args32[6];

			if (copyin((void *)rp->r_rbx, &args32,
			    sizeof (args32)) != 0) {
				/*
				 * Clear the argument vector so that the
				 * trace probe does not expose kernel
				 * memory.
				 */
				bzero(args, 6 * sizeof (uintptr_t));
				return (set_errno(EFAULT));
			}

			args[0] = args32[0];
			args[1] = args32[1];
			args[2] = args32[2];
			args[3] = args32[3];
			args[4] = args32[4];
			args[5] = args32[5];
		} else {
			args[0] = rp->r_rbx;
			args[1] = rp->r_rcx;
			args[2] = rp->r_rdx;
			args[3] = rp->r_rsi;
			args[4] = rp->r_rdi;
			args[5] = rp->r_rbp;
		}
	}

	return (0);
}

#else	/* !__amd64 */

static int
lx_emulate_args(klwp_t *lwp, const lx_sysent_t *s, uintptr_t *args)
{
	struct regs *rp = lwptoregs(lwp);

	/*
	 * If the system call takes 6 args, then libc has stashed them
	 * in memory at the address contained in %ebx. Except for some
	 * syscalls which store the 6th argument in %ebp.
	 */
	if (s->sy_narg == 6 && !(s->sy_flags & LX_SYS_EBPARG6)) {
		if (copyin((void *)rp->r_ebx, args, 6 * sizeof (uintptr_t)) !=
		    0) {
			/*
			 * Clear the argument vector so that the trace probe
			 * does not expose kernel memory.
			 */
			bzero(args, 6 * sizeof (uintptr_t));
			return (set_errno(EFAULT));
		}
	} else {
		args[0] = rp->r_ebx;
		args[1] = rp->r_ecx;
		args[2] = rp->r_edx;
		args[3] = rp->r_esi;
		args[4] = rp->r_edi;
		args[5] = rp->r_ebp;
	}

	return (0);
}
#endif

int
lx_syscall_return(klwp_t *lwp, int syscall_num, long ret)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	struct regs *rp = lwptoregs(lwp);
	int error = lwp->lwp_errno;

	if (error != EINTR) {
		/*
		 * If this system call was not interrupted, clear the system
		 * call restart flag before lx_setcontext() can pass it to
		 * usermode.
		 */
		lwpd->br_syscall_restart = B_FALSE;
	}

	if (error != 0) {
		/*
		 * Convert from illumos to Linux errno:
		 */
		if (error < 1 || error >= (sizeof (lx_stol_errno) /
		    sizeof (lx_stol_errno[0]))) {
			/*
			 * The provided error number is not valid.
			 */
			error = EINVAL;
		}
		ret = -lx_stol_errno[error];
	}

	/*
	 * 32-bit Linux system calls return via %eax; 64-bit calls return via
	 * %rax.
	 */
	rp->r_r0 = ret;

	/*
	 * Hold for the ptrace(2) "syscall-exit-stop" condition if required by
	 * PTRACE_SYSCALL.  Note that the register state may be modified by
	 * tracer.
	 */
	lx_ptrace_stop(LX_PR_SYSEXIT);

	/*
	 * Fire the DTrace "lx-syscall:::return" probe:
	 */
	lx_trace_sysreturn(syscall_num, ret);

	/*
	 * Clear errno for next time.  We do not clear "br_syscall_restart" or
	 * "br_syscall_num" as they are potentially used by "lx_savecontext()"
	 * in the signal delivery path.
	 */
	lwp->lwp_errno = 0;

	/*
	 * We want complete control of the registers on return from this
	 * emulated Linux system call:
	 */
	lwp->lwp_eosys = JUSTRETURN;
	curthread->t_post_sys = 1;
	aston(curthread);

	return (0);
}

/*
 * This function is used to override the processing of arguments and
 * invocation of a handler for emulated system calls, installed on each
 * branded LWP as "lwp_brand_syscall".  If this system call should use the
 * native path, we return 1.  If we handled this system call (and have made
 * arrangements with respect to post-return usermode register state) we
 * return 0.
 */
int
lx_syscall_enter(void)
{
	klwp_t *lwp = ttolwp(curthread);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	struct regs *rp = lwptoregs(lwp);
	int syscall_num;
	int error;
	long ret = 0;
	lx_sysent_t *s;
	uintptr_t args[6];
	unsigned int unsup_reason;

	/*
	 * If we got here, we should have an LWP-specific brand data
	 * structure.
	 */
	VERIFY(lwpd != NULL);

	if (lwpd->br_stack_mode != LX_STACK_MODE_BRAND) {
		/*
		 * The lwp is not in in BRAND execution mode, so we return
		 * to the regular native system call path.
		 */
		DTRACE_PROBE(brand__lx__syscall__hook__skip);
		return (1);
	}

	/*
	 * Clear the restartable system call flag.  This flag will be set
	 * on in the system call handler if the call is a candidate for
	 * a restart.  It will be saved by lx_setcontext() in the event
	 * that we take a signal, and used in the signal handling path
	 * to restart the system call iff SA_RESTART was set for this
	 * signal.  Save the system call number so that we can store it
	 * in the saved context if required.
	 */
	lwpd->br_syscall_restart = B_FALSE;
	lwpd->br_syscall_num = (int)rp->r_r0;

	/*
	 * Hold for the ptrace(2) "syscall-entry-stop" condition if traced by
	 * PTRACE_SYSCALL.  The system call number and arguments may be
	 * modified by the tracer.
	 */
	lx_ptrace_stop(LX_PR_SYSENTRY);

	/*
	 * Check that the system call number is within the bounds we expect.
	 */
	syscall_num = lwpd->br_syscall_num;
	if (syscall_num < 0 || syscall_num > LX_MAX_SYSCALL(lwp)) {
		set_errno(ENOTSUP);
		lx_syscall_return(lwp, syscall_num, -1);
		return (0);
	}

#if defined(_LP64)
	if (lwp_getdatamodel(lwp) == DATAMODEL_NATIVE) {
		s = &lx_sysent64[syscall_num];
	} else
#endif
	{
		s = &lx_sysent32[syscall_num];
	}

	/*
	 * Process the arguments for this system call and fire the DTrace
	 * "lx-syscall:::entry" probe:
	 */
	error = lx_emulate_args(lwp, s, args);
	lx_trace_sysenter(syscall_num, args);
	if (error != 0) {
		/*
		 * Could not read and process the arguments.  Return the error
		 * to the process.
		 */
		set_errno(error);
		lx_syscall_return(lwp, syscall_num, -1);
		return (0);
	}

	if (s->sy_callc != NULL) {
		/*
		 * Call the in-kernel handler for this Linux system call:
		 */
		ret = s->sy_callc(args[0], args[1], args[2], args[3], args[4],
		    args[5]);
		lx_syscall_return(lwp, syscall_num, ret);
		return (0);
	}

	/*
	 * There is no in-kernel handler.
	 */
	switch (unsup_reason = (s->sy_flags & LX_SYS_NOSYS_REASON)) {
	case NOSYS_USERMODE:
		/*
		 * Pass to the usermode emulation routine.
		 */
#if defined(_LP64)
		if (get_udatamodel() != DATAMODEL_NATIVE) {
			lx_emulate_user32(lwp, syscall_num, args);
		} else
#endif
		{
			lx_emulate_user(lwp, syscall_num, args);
		}
		return (0);

	default:
		/*
		 * We are not emulating this system call at all.
		 */
		VERIFY(unsup_reason < (sizeof (nosys_reasons) /
		    sizeof (*nosys_reasons)));
		lx_unsupported(nosys_reasons[unsup_reason]);

		set_errno(ENOTSUP);
		lx_syscall_return(lwp, syscall_num, -1);
		return (0);
	}
}

/*
 * Linux defines system call numbers for 32-bit x86 in the file:
 *   arch/x86/syscalls/syscall_32.tbl
 */
lx_sysent_t lx_sysent32[] = {
	{"nosys",	NULL,			NOSYS_NONE,	0}, /*  0 */
	{"exit",	NULL,			0,		1}, /*  1 */
	{"fork",	NULL,			0,		0}, /*  2 */
	{"read",	lx_read,		0,		3}, /*  3 */
	{"write",	lx_write,		0,		3}, /*  4 */
	{"open",	NULL,			0,		3}, /*  5 */
	{"close",	NULL,			0,		1}, /*  6 */
	{"waitpid",	lx_waitpid,		0,		3}, /*  7 */
	{"creat",	NULL,			0,		2}, /*  8 */
	{"link",	NULL,			0,		2}, /*  9 */
	{"unlink",	NULL,			0,		1}, /* 10 */
	{"execve",	NULL,			0,		3}, /* 11 */
	{"chdir",	NULL,			0,		1}, /* 12 */
	{"time",	NULL,			0,		1}, /* 13 */
	{"mknod",	NULL,			0,		3}, /* 14 */
	{"chmod",	NULL,			0,		2}, /* 15 */
	{"lchown16",	NULL,			0,		3}, /* 16 */
	{"break",	NULL,			NOSYS_OBSOLETE,	0}, /* 17 */
	{"stat",	NULL,			NOSYS_OBSOLETE,	0}, /* 18 */
	{"lseek",	NULL,			0,		3}, /* 19 */
	{"getpid",	lx_getpid,		0,		0}, /* 20 */
	{"mount",	NULL,			0,		5}, /* 21 */
	{"umount",	NULL,			0,		1}, /* 22 */
	{"setuid16",	NULL,			0,		1}, /* 23 */
	{"getuid16",	NULL,			0,		0}, /* 24 */
	{"stime",	NULL,			0,		1}, /* 25 */
	{"ptrace",	NULL,			0,		4}, /* 26 */
	{"alarm",	NULL,			0,		1}, /* 27 */
	{"fstat",	NULL,			NOSYS_OBSOLETE,	0}, /* 28 */
	{"pause",	NULL,			0,		0}, /* 29 */
	{"utime",	NULL,			0,		2}, /* 30 */
	{"stty",	NULL,			NOSYS_OBSOLETE,	0}, /* 31 */
	{"gtty",	NULL,			NOSYS_OBSOLETE,	0}, /* 32 */
	{"access",	NULL,			0,		2}, /* 33 */
	{"nice",	NULL,			0,		1}, /* 34 */
	{"ftime",	NULL,			NOSYS_OBSOLETE,	0}, /* 35 */
	{"sync",	NULL,			0, 		0}, /* 36 */
	{"kill",	lx_kill,		0,		2}, /* 37 */
	{"rename",	NULL,			0,		2}, /* 38 */
	{"mkdir",	NULL,			0,		2}, /* 39 */
	{"rmdir",	NULL,			0,		1}, /* 40 */
	{"dup",		NULL,			0,		1}, /* 41 */
	{"pipe",	lx_pipe,		0,		1}, /* 42 */
	{"times",	NULL,			0,		1}, /* 43 */
	{"prof",	NULL,			NOSYS_OBSOLETE,	0}, /* 44 */
	{"brk",		lx_brk,			0,		1}, /* 45 */
	{"setgid16",	NULL,			0,		1}, /* 46 */
	{"getgid16",	NULL,			0,		0}, /* 47 */
	{"signal",	NULL,			0,		2}, /* 48 */
	{"geteuid16",	NULL,			0,		0}, /* 49 */
	{"getegid16",	NULL,			0,		0}, /* 50 */
	{"acct",	NULL,			NOSYS_NO_EQUIV,	0}, /* 51 */
	{"umount2",	NULL,			0,		2}, /* 52 */
	{"lock",	NULL,			NOSYS_OBSOLETE,	0}, /* 53 */
	{"ioctl",	lx_ioctl,		0,		3}, /* 54 */
	{"fcntl",	NULL,			0,		3}, /* 55 */
	{"mpx",		NULL,			NOSYS_OBSOLETE,	0}, /* 56 */
	{"setpgid",	NULL,			0,		2}, /* 57 */
	{"ulimit",	NULL,			NOSYS_OBSOLETE,	0}, /* 58 */
	{"olduname",	NULL,			NOSYS_OBSOLETE,	0}, /* 59 */
	{"umask",	NULL,			0,		1}, /* 60 */
	{"chroot",	NULL,			0,		1}, /* 61 */
	{"ustat",	NULL,			NOSYS_OBSOLETE,	2}, /* 62 */
	{"dup2",	NULL,			0,		2}, /* 63 */
	{"getppid",	lx_getppid,		0,		0}, /* 64 */
	{"getpgrp",	NULL,			0,		0}, /* 65 */
	{"setsid",	NULL,			0,		0}, /* 66 */
	{"sigaction",	NULL,			0,		3}, /* 67 */
	{"sgetmask",	NULL,			NOSYS_OBSOLETE,	0}, /* 68 */
	{"ssetmask",	NULL,			NOSYS_OBSOLETE,	0}, /* 69 */
	{"setreuid16",	NULL,			0,		2}, /* 70 */
	{"setregid16",	NULL,			0,		2}, /* 71 */
	{"sigsuspend",	NULL,			0,		1}, /* 72 */
	{"sigpending",	NULL,			0,		1}, /* 73 */
	{"sethostname",	NULL,			0,		2}, /* 74 */
	{"setrlimit",	NULL,			0,		2}, /* 75 */
	{"getrlimit",	NULL,			0,		2}, /* 76 */
	{"getrusage",	NULL,			0,		2}, /* 77 */
	{"gettimeofday", NULL, 			0,		2}, /* 78 */
	{"settimeofday", NULL, 			0,		2}, /* 79 */
	{"getgroups16",	NULL,			0,		2}, /* 80 */
	{"setgroups16",	NULL,			0,		2}, /* 81 */
	{"select",	NULL,			NOSYS_OBSOLETE,	0}, /* 82 */
	{"symlink",	NULL,			0,		2}, /* 83 */
	{"oldlstat",	NULL,			NOSYS_OBSOLETE,	0}, /* 84 */
	{"readlink",	NULL,			0,		3}, /* 85 */
	{"uselib",	NULL,			NOSYS_KERNEL,	0}, /* 86 */
	{"swapon",	NULL,			NOSYS_KERNEL,	0}, /* 87 */
	{"reboot",	NULL,			0,		4}, /* 88 */
	{"readdir",	NULL,			0,		3}, /* 89 */
	{"mmap",	NULL,			0,		6}, /* 90 */
	{"munmap",	NULL,			0,		2}, /* 91 */
	{"truncate",	NULL,			0,		2}, /* 92 */
	{"ftruncate",	NULL,			0,		2}, /* 93 */
	{"fchmod",	NULL,			0,		2}, /* 94 */
	{"fchown16",	NULL,			0,		3}, /* 95 */
	{"getpriority",	NULL,			0,		2}, /* 96 */
	{"setpriority",	NULL,			0,		3}, /* 97 */
	{"profil",	NULL,			NOSYS_NO_EQUIV,	0}, /* 98 */
	{"statfs",	NULL,			0,		2}, /* 99 */
	{"fstatfs",	NULL,			0,		2}, /* 100 */
	{"ioperm",	NULL,			NOSYS_NO_EQUIV,	0}, /* 101 */
	{"socketcall",	NULL,			0,		2}, /* 102 */
	{"syslog",	NULL,			0,		3}, /* 103 */
	{"setitimer",	NULL,			0,		3}, /* 104 */
	{"getitimer",	NULL,			0,		2}, /* 105 */
	{"stat",	NULL,			0,		2}, /* 106 */
	{"lstat",	NULL,			0,		2}, /* 107 */
	{"fstat",	NULL,			0,		2}, /* 108 */
	{"uname",	NULL,			NOSYS_OBSOLETE,	0}, /* 109 */
	{"oldiopl",	NULL,			NOSYS_NO_EQUIV,	0}, /* 110 */
	{"vhangup",	NULL,			0,		0}, /* 111 */
	{"idle",	NULL,			NOSYS_NO_EQUIV,	0}, /* 112 */
	{"vm86old",	NULL,			NOSYS_OBSOLETE,	0}, /* 113 */
	{"wait4",	lx_wait4,		0,		4}, /* 114 */
	{"swapoff",	NULL,			NOSYS_KERNEL,	0}, /* 115 */
	{"sysinfo",	lx_sysinfo32,		0,		1}, /* 116 */
	{"ipc",		NULL,			0,		5}, /* 117 */
	{"fsync",	NULL,			0,		1}, /* 118 */
	{"sigreturn",	NULL,			0,		1}, /* 119 */
	{"clone",	NULL,			0,		5}, /* 120 */
	{"setdomainname", NULL,			0,		2}, /* 121 */
	{"uname",	NULL,			0,		1}, /* 122 */
	{"modify_ldt",	lx_modify_ldt,		0,		3}, /* 123 */
	{"adjtimex",	NULL,			0,		1}, /* 124 */
	{"mprotect",	NULL,			0,		3}, /* 125 */
	{"sigprocmask",	NULL,			0,		3}, /* 126 */
	{"create_module", NULL,			NOSYS_KERNEL,	0}, /* 127 */
	{"init_module",	NULL,			NOSYS_KERNEL,	0}, /* 128 */
	{"delete_module", NULL,			NOSYS_KERNEL,	0}, /* 129 */
	{"get_kernel_syms", NULL,		NOSYS_KERNEL,	0}, /* 130 */
	{"quotactl",	NULL,			NOSYS_KERNEL,	0}, /* 131 */
	{"getpgid",	NULL,			0,		1}, /* 132 */
	{"fchdir",	NULL,			0,		1}, /* 133 */
	{"bdflush",	NULL,			NOSYS_KERNEL,	0}, /* 134 */
	{"sysfs",	NULL,			0,		3}, /* 135 */
	{"personality",	NULL,			0,		1}, /* 136 */
	{"afs_syscall",	NULL,			NOSYS_KERNEL,	0}, /* 137 */
	{"setfsuid16",	NULL,			0,		1}, /* 138 */
	{"setfsgid16",	NULL,			0,		1}, /* 139 */
	{"llseek",	NULL,			0,		5}, /* 140 */
	{"getdents",	NULL,			0,		3}, /* 141 */
	{"select",	NULL,			0,		5}, /* 142 */
	{"flock",	NULL,			0,		2}, /* 143 */
	{"msync",	NULL,			0,		3}, /* 144 */
	{"readv",	NULL,			0,		3}, /* 145 */
	{"writev",	NULL,			0,		3}, /* 146 */
	{"getsid",	NULL,			0,		1}, /* 147 */
	{"fdatasync",	NULL,			0,		1}, /* 148 */
	{"sysctl",	NULL,			0,		1}, /* 149 */
	{"mlock",	NULL,			0,		2}, /* 150 */
	{"munlock",	NULL,			0,		2}, /* 151 */
	{"mlockall",	NULL,			0,		1}, /* 152 */
	{"munlockall",	NULL,			0,		0}, /* 153 */
	{"sched_setparam", NULL,		0,		2}, /* 154 */
	{"sched_getparam", NULL,		0,		2}, /* 155 */
	{"sched_setscheduler", NULL,		0,		3}, /* 156 */
	{"sched_getscheduler", NULL,		0,		1}, /* 157 */
	{"sched_yield",	lx_sched_yield,		0,		0}, /* 158 */
	{"sched_get_priority_max", NULL, 	0,		1}, /* 159 */
	{"sched_get_priority_min", NULL, 	0,		1}, /* 160 */
	{"sched_rr_get_interval", NULL, 	0,		2}, /* 161 */
	{"nanosleep",	NULL,			0,		2}, /* 162 */
	{"mremap",	NULL,			0,		5}, /* 163 */
	{"setresuid16",	lx_setresuid16,		0,		3}, /* 164 */
	{"getresuid16",	NULL,			0,		3}, /* 165 */
	{"vm86",	NULL,			NOSYS_NO_EQUIV,	0}, /* 166 */
	{"query_module", NULL,			0,		5}, /* 167 */
	{"poll",	NULL,			0,		3}, /* 168 */
	{"nfsservctl",	NULL,			NOSYS_KERNEL,	0}, /* 169 */
	{"setresgid16",	lx_setresgid16,		0,		3}, /* 170 */
	{"getresgid16",	NULL,			0,		3}, /* 171 */
	{"prctl",	NULL,			0,		5}, /* 172 */
	{"rt_sigreturn", NULL,			0,		0}, /* 173 */
	{"rt_sigaction", NULL,			0,		4}, /* 174 */
	{"rt_sigprocmask", NULL,		0,		4}, /* 175 */
	{"rt_sigpending", NULL,			0,		2}, /* 176 */
	{"rt_sigtimedwait", NULL,		0,		4}, /* 177 */
	{"rt_sigqueueinfo", NULL,		0,		3}, /* 178 */
	{"rt_sigsuspend", NULL,			0,		2}, /* 179 */
	{"pread64",	NULL,			0,		5}, /* 180 */
	{"pwrite64",	NULL,			0,		5}, /* 181 */
	{"chown16",	NULL,			0,		3}, /* 182 */
	{"getcwd",	NULL,			0,		2}, /* 183 */
	{"capget",	NULL,			0,		2}, /* 184 */
	{"capset",	NULL,			0,		2}, /* 185 */
	{"sigaltstack",	NULL,			0,		2}, /* 186 */
	{"sendfile",	NULL,			0,		4}, /* 187 */
	{"getpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 188 */
	{"putpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 189 */
	{"vfork",	NULL,			0,		0}, /* 190 */
	{"getrlimit",	NULL,			0,		2}, /* 191 */
	{"mmap2",	NULL,			LX_SYS_EBPARG6,	6}, /* 192 */
	{"truncate64",	NULL,			0,		3}, /* 193 */
	{"ftruncate64",	NULL,			0,		3}, /* 194 */
	{"stat64",	NULL,			0,		2}, /* 195 */
	{"lstat64",	NULL,			0,		2}, /* 196 */
	{"fstat64",	NULL,			0,		2}, /* 197 */
	{"lchown",	NULL,			0,		3}, /* 198 */
	{"getuid",	NULL,			0,		0}, /* 199 */
	{"getgid",	NULL,			0,		0}, /* 200 */
	{"geteuid",	NULL,			0,		0}, /* 201 */
	{"getegid",	NULL,			0,		0}, /* 202 */
	{"setreuid",	NULL,			0,		0}, /* 203 */
	{"setregid",	NULL,			0,		0}, /* 204 */
	{"getgroups",	NULL,			0,		2}, /* 205 */
	{"setgroups",	NULL,			0,		2}, /* 206 */
	{"fchown",	NULL,			0,		3}, /* 207 */
	{"setresuid",	lx_setresuid,		0,		3}, /* 208 */
	{"getresuid",	NULL,			0,		3}, /* 209 */
	{"setresgid",	lx_setresgid,		0,		3}, /* 210 */
	{"getresgid",	NULL,			0,		3}, /* 211 */
	{"chown",	NULL,			0,		3}, /* 212 */
	{"setuid",	NULL,			0,		1}, /* 213 */
	{"setgid",	NULL,			0,		1}, /* 214 */
	{"setfsuid",	NULL,			0,		1}, /* 215 */
	{"setfsgid",	NULL,			0,		1}, /* 216 */
	{"pivot_root",	NULL,			NOSYS_KERNEL,	0}, /* 217 */
	{"mincore",	NULL,			0,		3}, /* 218 */
	{"madvise",	NULL,			0,		3}, /* 219 */
	{"getdents64",	NULL,			0,		3}, /* 220 */
	{"fcntl64",	NULL,			0,		3}, /* 221 */
	{"tux",		NULL,			NOSYS_NO_EQUIV,	0}, /* 222 */
	{"security",	NULL,			NOSYS_NO_EQUIV,	0}, /* 223 */
	{"gettid",	lx_gettid,		0,		0}, /* 224 */
	{"readahead",	NULL,			NOSYS_NO_EQUIV,	0}, /* 225 */
	{"setxattr",	NULL,			NOSYS_NO_EQUIV,	0}, /* 226 */
	{"lsetxattr",	NULL,			NOSYS_NO_EQUIV,	0}, /* 227 */
	{"fsetxattr",	NULL,			NOSYS_NO_EQUIV,	0}, /* 228 */
	{"getxattr",	lx_xattr,		0,		4}, /* 229 */
	{"lgetxattr",	lx_xattr,		0,		4}, /* 230 */
	{"fgetxattr",	lx_xattr,		0,		4}, /* 231 */
	{"listxattr",	lx_xattr,		0,		3}, /* 232 */
	{"llistxattr",	lx_xattr,		0,		3}, /* 233 */
	{"flistxattr",	lx_xattr,		0,		3}, /* 234 */
	{"removexattr",	lx_xattr,		0,		2}, /* 235 */
	{"lremovexattr", lx_xattr,		0,		2}, /* 236 */
	{"fremovexattr", lx_xattr,		0,		2}, /* 237 */
	{"tkill",	lx_tkill,		0,		2}, /* 238 */
	{"sendfile64",	NULL,			0,		4}, /* 239 */
	{"futex",	lx_futex,		LX_SYS_EBPARG6,	6}, /* 240 */
	{"sched_setaffinity", NULL, 		0,		3}, /* 241 */
	{"sched_getaffinity", NULL, 		0,		3}, /* 242 */
	{"set_thread_area", lx_set_thread_area,	0,		1}, /* 243 */
	{"get_thread_area", lx_get_thread_area,	0,		1}, /* 244 */
	{"io_setup",	NULL,			NOSYS_NO_EQUIV,	0}, /* 245 */
	{"io_destroy",	NULL,			NOSYS_NO_EQUIV,	0}, /* 246 */
	{"io_getevents", NULL,			NOSYS_NO_EQUIV,	0}, /* 247 */
	{"io_submit",	NULL,			NOSYS_NO_EQUIV,	0}, /* 248 */
	{"io_cancel",	NULL,			NOSYS_NO_EQUIV,	0}, /* 249 */
	{"fadvise64",	NULL,			0,		4}, /* 250 */
	{"nosys",	NULL,			0,		0}, /* 251 */
	{"group_exit",	NULL,			0,		1}, /* 252 */
	{"lookup_dcookie", NULL,		NOSYS_NO_EQUIV,	0}, /* 253 */
	{"epoll_create", NULL,			0,		1}, /* 254 */
	{"epoll_ctl",	NULL,			0,		4}, /* 255 */
	{"epoll_wait",	NULL,			0,		4}, /* 256 */
	{"remap_file_pages", NULL,		NOSYS_NO_EQUIV,	0}, /* 257 */
	{"set_tid_address", lx_set_tid_address,	0,		1}, /* 258 */
	{"timer_create", NULL,			0,		3}, /* 259 */
	{"timer_settime", NULL,			0,		4}, /* 260 */
	{"timer_gettime", NULL,			0,		2}, /* 261 */
	{"timer_getoverrun", NULL,		0,		1}, /* 262 */
	{"timer_delete", NULL,			0,		1}, /* 263 */
	{"clock_settime", NULL,			0,		2}, /* 264 */
	{"clock_gettime", NULL,			0,		2}, /* 265 */
	{"clock_getres", NULL,			0,		2}, /* 266 */
	{"clock_nanosleep", NULL,		0,		4}, /* 267 */
	{"statfs64",	NULL,			0,		2}, /* 268 */
	{"fstatfs64",	NULL,			0,		2}, /* 269 */
	{"tgkill",	lx_tgkill,		0,		3}, /* 270 */

/*
 * The following system calls only exist in kernel 2.6 and greater:
 */
	{"utimes",	NULL,			0,		2}, /* 271 */
	{"fadvise64_64", NULL, 			0,		4}, /* 272 */
	{"vserver",	NULL,			NOSYS_NULL,	0}, /* 273 */
	{"mbind",	NULL,			NOSYS_NULL,	0}, /* 274 */
	{"get_mempolicy", NULL,			NOSYS_NULL,	0}, /* 275 */
	{"set_mempolicy", NULL,			NOSYS_NULL,	0}, /* 276 */
	{"mq_open",	NULL,			NOSYS_NULL,	0}, /* 277 */
	{"mq_unlink",	NULL,			NOSYS_NULL,	0}, /* 278 */
	{"mq_timedsend", NULL,			NOSYS_NULL,	0}, /* 279 */
	{"mq_timedreceive", NULL,		NOSYS_NULL,	0}, /* 280 */
	{"mq_notify",	NULL,			NOSYS_NULL,	0}, /* 281 */
	{"mq_getsetattr", NULL,			NOSYS_NULL,	0}, /* 282 */
	{"kexec_load",	NULL,			NOSYS_NULL,	0}, /* 283 */
	{"waitid",	lx_waitid,		0,		4}, /* 284 */
	{"sys_setaltroot", NULL,		NOSYS_NULL,	0}, /* 285 */
	{"add_key",	NULL,			NOSYS_NULL,	0}, /* 286 */
	{"request_key",	NULL,			NOSYS_NULL,	0}, /* 287 */
	{"keyctl",	NULL,			NOSYS_NULL,	0}, /* 288 */
	{"ioprio_set",	NULL,			NOSYS_NULL,	0}, /* 289 */
	{"ioprio_get",	NULL,			NOSYS_NULL,	0}, /* 290 */
	{"inotify_init", NULL,			0,		0}, /* 291 */
	{"inotify_add_watch", NULL,		0,		3}, /* 292 */
	{"inotify_rm_watch", NULL,		0,		2}, /* 293 */
	{"migrate_pages", NULL,			NOSYS_NULL,	0}, /* 294 */
	{"openat",	NULL,			0,		4}, /* 295 */
	{"mkdirat",	NULL,			0,		3}, /* 296 */
	{"mknodat",	NULL,			0,		4}, /* 297 */
	{"fchownat",	NULL,			0,		5}, /* 298 */
	{"futimesat",	NULL,			0,		3}, /* 299 */
	{"fstatat64",	NULL,			0,		4}, /* 300 */
	{"unlinkat",	NULL,			0,		3}, /* 301 */
	{"renameat",	NULL,			0,		4}, /* 302 */
	{"linkat",	NULL,			0,		5}, /* 303 */
	{"symlinkat",	NULL,			0,		3}, /* 304 */
	{"readlinkat",	NULL,			0,		4}, /* 305 */
	{"fchmodat",	NULL,			0,		4}, /* 306 */
	{"faccessat",	NULL,			0,		4}, /* 307 */
	{"pselect6",	NULL,			LX_SYS_EBPARG6,	6}, /* 308 */
	{"ppoll",	NULL,			0,		5}, /* 309 */
	{"unshare",	NULL,			NOSYS_NULL,	0}, /* 310 */
	{"set_robust_list", NULL,		NOSYS_NULL,	0}, /* 311 */
	{"get_robust_list", NULL,		NOSYS_NULL,	0}, /* 312 */
	{"splice",	NULL,			NOSYS_NULL,	0}, /* 313 */
	{"sync_file_range", NULL,		NOSYS_NULL,	0}, /* 314 */
	{"tee",		NULL,			NOSYS_NULL,	0}, /* 315 */
	{"vmsplice",	NULL,			NOSYS_NULL,	0}, /* 316 */
	{"move_pages",	NULL,			NOSYS_NULL,	0}, /* 317 */
	{"getcpu",	NULL,			0,		3}, /* 318 */
	{"epoll_pwait",	NULL,			0,		5}, /* 319 */
	{"utimensat",	NULL,			0,		4}, /* 320 */
	{"signalfd",	NULL,			NOSYS_NULL,	0}, /* 321 */
	{"timerfd_create", NULL,		NOSYS_NULL,	0}, /* 322 */
	{"eventfd",	NULL,			0,		1}, /* 323 */
	{"fallocate",	NULL,			NOSYS_NULL,	0}, /* 324 */
	{"timerfd_settime", NULL,		NOSYS_NULL,	0}, /* 325 */
	{"timerfd_gettime", NULL,		NOSYS_NULL,	0}, /* 326 */
	{"signalfd4",	NULL,			NOSYS_NULL,	0}, /* 327 */
	{"eventfd2",	NULL,			0,		2}, /* 328 */
	{"epoll_create1", NULL,			0,		1}, /* 329 */
	{"dup3",	NULL,			0,		3}, /* 330 */
	{"pipe2",	lx_pipe2,		0,		2}, /* 331 */
	{"inotify_init1", NULL,			0,		1}, /* 332 */
	{"preadv",	NULL,			NOSYS_NULL,	0}, /* 333 */
	{"pwritev",	NULL,			NOSYS_NULL,	0}, /* 334 */
	{"rt_tgsigqueueinfo", NULL,		0,		4}, /* 335 */
	{"perf_event_open", NULL,		NOSYS_NULL,	0}, /* 336 */
	{"recvmmsg",	NULL,			NOSYS_NULL,	0}, /* 337 */
	{"fanotify_init", NULL,			NOSYS_NULL,	0}, /* 338 */
	{"fanotify_mark", NULL,			NOSYS_NULL,	0}, /* 339 */
	{"prlimit64",	NULL,			0,		4}, /* 340 */
	{"name_to_handle_at", NULL,		NOSYS_NULL,	0}, /* 341 */
	{"open_by_handle_at", NULL,		NOSYS_NULL,	0}, /* 342 */
	{"clock_adjtime", NULL,			NOSYS_NULL,	0}, /* 343 */
	{"syncfs",	NULL,			NOSYS_NULL,	0}, /* 344 */
	{"sendmmsg",	NULL,			NOSYS_NULL,	0}, /* 345 */
	{"setns",	NULL,			NOSYS_NULL,	0}, /* 346 */
	{"process_vm_readv", NULL,		NOSYS_NULL,	0}, /* 347 */
	{"process_vm_writev", NULL,		NOSYS_NULL,	0}, /* 348 */
	{"kcmp",	NULL,			NOSYS_NULL,	0}, /* 349 */
	{"finit_module", NULL,			NOSYS_NULL,	0}, /* 350 */
	{"sched_setattr", NULL,			NOSYS_NULL,	0}, /* 351 */
	{"sched_getattr", NULL,			NOSYS_NULL,	0}, /* 352 */
	{"renameat2",	NULL,			NOSYS_NULL,	0}, /* 353 */
	{"seccomp",	NULL,			NOSYS_NULL,	0}, /* 354 */
	{"getrandom",	NULL,			NOSYS_NULL,	0}, /* 355 */
	{"memfd_create", NULL,			NOSYS_NULL,	0}, /* 356 */
	{"bpf",		NULL,			NOSYS_NULL,	0}, /* 357 */
	{"execveat",	NULL,			NOSYS_NULL,	0}, /* 358 */
};

#if defined(_LP64)
/*
 * Linux defines system call numbers for 64-bit x86 in the file:
 *   arch/x86/syscalls/syscall_64.tbl
 */
lx_sysent_t lx_sysent64[] = {
	{"read",	lx_read,		0,		3}, /* 0 */
	{"write",	lx_write,		0,		3}, /* 1 */
	{"open",	NULL,			0,		3}, /* 2 */
	{"close",	NULL,			0,		1}, /* 3 */
	{"stat",	NULL,			0,		2}, /* 4 */
	{"fstat",	NULL,			0,		2}, /* 5 */
	{"lstat",	NULL,			0,		2}, /* 6 */
	{"poll",	NULL,			0,		3}, /* 7 */
	{"lseek",	NULL,			0,		3}, /* 8 */
	{"mmap",	NULL,			0,		6}, /* 9 */
	{"mprotect",	NULL,			0,		3}, /* 10 */
	{"munmap",	NULL,			0,		2}, /* 11 */
	{"brk",		lx_brk,			0,		1}, /* 12 */
	{"rt_sigaction", NULL,			0,		4}, /* 13 */
	{"rt_sigprocmask", NULL,		0,		4}, /* 14 */
	{"rt_sigreturn", NULL,			0,		0}, /* 15 */
	{"ioctl",	lx_ioctl,		0,		3}, /* 16 */
	{"pread64",	NULL,			0,		4}, /* 17 */
	{"pwrite64",	NULL,			0,		4}, /* 18 */
	{"readv",	NULL,			0,		3}, /* 19 */
	{"writev",	NULL,			0,		3}, /* 20 */
	{"access",	NULL,			0,		2}, /* 21 */
	{"pipe",	lx_pipe,		0,		1}, /* 22 */
	{"select",	NULL,			0,		5}, /* 23 */
	{"sched_yield",	lx_sched_yield,		0,		0}, /* 24 */
	{"mremap",	NULL,			0,		5}, /* 25 */
	{"msync",	NULL,			0,		3}, /* 26 */
	{"mincore",	NULL,			0,		3}, /* 27 */
	{"madvise",	NULL,			0,		3}, /* 28 */
	{"shmget",	NULL,			0,		3}, /* 29 */
	{"shmat",	NULL,			0,		4}, /* 30 */
	{"shmctl",	NULL,			0,		3}, /* 31 */
	{"dup",		NULL,			0,		1}, /* 32 */
	{"dup2",	NULL,			0,		2}, /* 33 */
	{"pause",	NULL,			0,		0}, /* 34 */
	{"nanosleep",	NULL,			0,		2}, /* 35 */
	{"getitimer",	NULL,			0,		2}, /* 36 */
	{"alarm",	NULL,			0,		1}, /* 37 */
	{"setitimer",	NULL,			0,		3}, /* 38 */
	{"getpid",	lx_getpid,		0,		0}, /* 39 */
	{"sendfile",	NULL,			0,		4}, /* 40 */
	{"socket",	NULL,			0,		3}, /* 41 */
	{"connect",	NULL,			0,		3}, /* 42 */
	{"accept",	NULL,			0,		3}, /* 43 */
	{"sendto",	NULL,			0,		6}, /* 44 */
	{"recvfrom",	NULL,			0,		6}, /* 45 */
	{"sendmsg",	NULL,			0,		3}, /* 46 */
	{"recvmsg",	NULL,			0,		3}, /* 47 */
	{"shutdown",	NULL,			0,		2}, /* 48 */
	{"bind",	NULL,			0,		3}, /* 49 */
	{"listen",	NULL,			0,		2}, /* 50 */
	{"getsockname",	NULL,			0,		3}, /* 51 */
	{"getpeername",	NULL,			0,		3}, /* 52 */
	{"socketpair",	NULL,			0,		4}, /* 53 */
	{"setsockopt",	NULL,			0,		5}, /* 54 */
	{"getsockopt",	NULL,			0,		5}, /* 55 */
	{"clone",	NULL,			0,		5}, /* 56 */
	{"fork",	NULL,			0,		0}, /* 57 */
	{"vfork",	NULL,			0,		0}, /* 58 */
	{"execve",	NULL,			0,		3}, /* 59 */
	{"exit",	NULL,			0,		1}, /* 60 */
	{"wait4",	lx_wait4,		0,		4}, /* 61 */
	{"kill",	lx_kill,		0,		2}, /* 62 */
	{"uname",	NULL,			0,		1}, /* 63 */
	{"semget",	NULL,			0,		3}, /* 64 */
	{"semop",	NULL,			0,		3}, /* 65 */
	{"semctl",	NULL,			0,		4}, /* 66 */
	{"shmdt",	NULL,			0,		1}, /* 67 */
	{"msgget",	NULL,			0,		2}, /* 68 */
	{"msgsnd",	NULL,			0,		4}, /* 69 */
	{"msgrcv",	NULL,			0,		5}, /* 70 */
	{"msgctl",	NULL,			0,		3}, /* 71 */
	{"fcntl",	NULL,			0,		3}, /* 72 */
	{"flock",	NULL,			0,		2}, /* 73 */
	{"fsync",	NULL,			0,		1}, /* 74 */
	{"fdatasync",	NULL,			0,		1}, /* 75 */
	{"truncate",	NULL,			0,		2}, /* 76 */
	{"ftruncate",	NULL,			0,		2}, /* 77 */
	{"getdents",	NULL,			0,		3}, /* 78 */
	{"getcwd",	NULL,			0,		2}, /* 79 */
	{"chdir",	NULL,			0,		1}, /* 80 */
	{"fchdir",	NULL,			0,		1}, /* 81 */
	{"rename",	NULL,			0,		2}, /* 82 */
	{"mkdir",	NULL,			0,		2}, /* 83 */
	{"rmdir",	NULL,			0,		1}, /* 84 */
	{"creat",	NULL,			0,		2}, /* 85 */
	{"link",	NULL,			0,		2}, /* 86 */
	{"unlink",	NULL,			0,		1}, /* 87 */
	{"symlink",	NULL,			0,		2}, /* 88 */
	{"readlink",	NULL,			0,		3}, /* 89 */
	{"chmod",	NULL,			0,		2}, /* 90 */
	{"fchmod",	NULL,			0,		2}, /* 91 */
	{"chown",	NULL,			0,		3}, /* 92 */
	{"fchown",	NULL,			0,		3}, /* 93 */
	{"lchown",	NULL,			0,		3}, /* 94 */
	{"umask",	NULL,			0,		1}, /* 95 */
	{"gettimeofday", NULL,			0,		2}, /* 96 */
	{"getrlimit",	NULL,			0,		2}, /* 97 */
	{"getrusage",	NULL,			0,		2}, /* 98 */
	{"sysinfo",	lx_sysinfo64,		0,		1}, /* 99 */
	{"times",	NULL,			0,		1}, /* 100 */
	{"ptrace",	NULL,			0,		4}, /* 101 */
	{"getuid",	NULL,			0,		0}, /* 102 */
	{"syslog",	NULL,			0,		3}, /* 103 */
	{"getgid",	NULL,			0,		0}, /* 104 */
	{"setuid",	NULL,			0,		1}, /* 105 */
	{"setgid",	NULL,			0,		1}, /* 106 */
	{"geteuid",	NULL,			0,		0}, /* 107 */
	{"getegid",	NULL,			0,		0}, /* 108 */
	{"setpgid",	NULL,			0,		2}, /* 109 */
	{"getppid",	lx_getppid,		0,		0}, /* 110 */
	{"getpgrp",	NULL,			0,		0}, /* 111 */
	{"setsid",	NULL,			0,		0}, /* 112 */
	{"setreuid",	NULL,			0,		0}, /* 113 */
	{"setregid",	NULL,			0,		0}, /* 114 */
	{"getgroups",	NULL,			0,		2}, /* 115 */
	{"setgroups",	NULL,			0,		2}, /* 116 */
	{"setresuid",	lx_setresuid,		0,		3}, /* 117 */
	{"getresuid",	NULL,			0,		3}, /* 118 */
	{"setresgid",	lx_setresgid,		0,		3}, /* 119 */
	{"getresgid",	NULL,			0,		3}, /* 120 */
	{"getpgid",	NULL,			0,		1}, /* 121 */
	{"setfsuid",	NULL,			0,		1}, /* 122 */
	{"setfsgid",	NULL,			0,		1}, /* 123 */
	{"getsid",	NULL,			0,		1}, /* 124 */
	{"capget",	NULL,			0,		2}, /* 125 */
	{"capset",	NULL,			0,		2}, /* 126 */
	{"rt_sigpending", NULL,			0,		2}, /* 127 */
	{"rt_sigtimedwait", NULL,		0,		4}, /* 128 */
	{"rt_sigqueueinfo", NULL,		0,		3}, /* 129 */
	{"rt_sigsuspend", NULL,			0,		2}, /* 130 */
	{"sigaltstack",	NULL,			0,		2}, /* 131 */
	{"utime",	NULL,			0,		2}, /* 132 */
	{"mknod",	NULL,			0,		3}, /* 133 */
	{"uselib",	NULL,			NOSYS_KERNEL,	0}, /* 134 */
	{"personality",	NULL,			0,		1}, /* 135 */
	{"ustat",	NULL,			NOSYS_OBSOLETE,	2}, /* 136 */
	{"statfs",	NULL,			0,		2}, /* 137 */
	{"fstatfs",	NULL,			0,		2}, /* 138 */
	{"sysfs",	NULL,			0,		3}, /* 139 */
	{"getpriority",	NULL,			0,		2}, /* 140 */
	{"setpriority",	NULL,			0,		3}, /* 141 */
	{"sched_setparam", NULL,		0,		2}, /* 142 */
	{"sched_getparam", NULL,		0,		2}, /* 143 */
	{"sched_setscheduler", NULL,		0,		3}, /* 144 */
	{"sched_getscheduler", NULL,		0,		1}, /* 145 */
	{"sched_get_priority_max", NULL,	0,		1}, /* 146 */
	{"sched_get_priority_min", NULL,	0,		1}, /* 147 */
	{"sched_rr_get_interval", NULL,		0,		2}, /* 148 */
	{"mlock",	NULL,			0,		2}, /* 149 */
	{"munlock",	NULL,			0,		2}, /* 150 */
	{"mlockall",	NULL,			0,		1}, /* 151 */
	{"munlockall",	NULL,			0,		0}, /* 152 */
	{"vhangup",	NULL,			0,		0}, /* 153 */
	{"modify_ldt",	lx_modify_ldt,		0,		3}, /* 154 */
	{"pivot_root",	NULL,			NOSYS_KERNEL,	0}, /* 155 */
	{"sysctl",	NULL,			0,		1}, /* 156 */
	{"prctl",	NULL,			0,		5}, /* 157 */
	{"arch_prctl",	lx_arch_prctl,		0,		2}, /* 158 */
	{"adjtimex",	NULL,			0,		1}, /* 159 */
	{"setrlimit",	NULL,			0,		2}, /* 160 */
	{"chroot",	NULL,			0,		1}, /* 161 */
	{"sync",	NULL,			0,		0}, /* 162 */
	{"acct",	NULL,			NOSYS_NO_EQUIV,	0}, /* 163 */
	{"settimeofday", NULL,			0,		2}, /* 164 */
	{"mount",	NULL,			0,		5}, /* 165 */
	{"umount2",	NULL,			0,		2}, /* 166 */
	{"swapon",	NULL,			NOSYS_KERNEL,	0}, /* 167 */
	{"swapoff",	NULL,			NOSYS_KERNEL,	0}, /* 168 */
	{"reboot",	NULL,			0,		4}, /* 169 */
	{"sethostname",	NULL,			0,		2}, /* 170 */
	{"setdomainname", NULL,			0,		2}, /* 171 */
	{"iopl",	NULL,			NOSYS_NO_EQUIV,	0}, /* 172 */
	{"ioperm",	NULL,			NOSYS_NO_EQUIV,	0}, /* 173 */
	{"create_module", NULL,			NOSYS_KERNEL,	0}, /* 174 */
	{"init_module",	NULL,			NOSYS_KERNEL,	0}, /* 175 */
	{"delete_module", NULL,			NOSYS_KERNEL,	0}, /* 176 */
	{"get_kernel_syms", NULL,		NOSYS_KERNEL,	0}, /* 177 */
	{"query_module", NULL,			0,		5}, /* 178 */
	{"quotactl",	NULL,			NOSYS_KERNEL,	0}, /* 179 */
	{"nfsservctl",	NULL,			NOSYS_KERNEL,	0}, /* 180 */
	{"getpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 181 */
	{"putpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 182 */
	{"afs_syscall",	NULL,			NOSYS_KERNEL,	0}, /* 183 */
	{"tux",		NULL,			NOSYS_NO_EQUIV,	0}, /* 184 */
	{"security",	NULL,			NOSYS_NO_EQUIV,	0}, /* 185 */
	{"gettid",	lx_gettid,		0,		0}, /* 186 */
	{"readahead",	NULL,			NOSYS_NO_EQUIV,	0}, /* 187 */
	{"setxattr",	NULL,			NOSYS_NO_EQUIV,	0}, /* 188 */
	{"lsetxattr",	NULL,			NOSYS_NO_EQUIV,	0}, /* 189 */
	{"fsetxattr",	NULL,			NOSYS_NO_EQUIV,	0}, /* 190 */
	{"getxattr",	lx_xattr,		0,		4}, /* 191 */
	{"lgetxattr",	lx_xattr,		0,		4}, /* 192 */
	{"fgetxattr",	lx_xattr,		0,		4}, /* 193 */
	{"listxattr",	lx_xattr,		0,		3}, /* 194 */
	{"llistxattr",	lx_xattr,		0,		3}, /* 195 */
	{"flistxattr",	lx_xattr,		0,		3}, /* 196 */
	{"removexattr",	lx_xattr,		0,		2}, /* 197 */
	{"lremovexattr", lx_xattr,		0,		2}, /* 198 */
	{"fremovexattr", lx_xattr,		0,		2}, /* 199 */
	{"tkill",	lx_tkill,		0,		2}, /* 200 */
	{"time",	NULL,			0,		1}, /* 201 */
	{"futex",	lx_futex,		0,		6}, /* 202 */
	{"sched_setaffinity", NULL,		0,		3}, /* 203 */
	{"sched_getaffinity", NULL,		0,		3}, /* 204 */
	{"set_thread_area", lx_set_thread_area, 0,		1}, /* 205 */
	{"io_setup",	NULL,			NOSYS_NO_EQUIV,	0}, /* 206 */
	{"io_destroy",	NULL,			NOSYS_NO_EQUIV,	0}, /* 207 */
	{"io_getevents", NULL,			NOSYS_NO_EQUIV,	0}, /* 208 */
	{"io_submit",	NULL,			NOSYS_NO_EQUIV,	0}, /* 209 */
	{"io_cancel",	NULL,			NOSYS_NO_EQUIV,	0}, /* 210 */
	{"get_thread_area", lx_get_thread_area,	0,		1}, /* 211 */
	{"lookup_dcookie", NULL,		NOSYS_NO_EQUIV,	0}, /* 212 */
	{"epoll_create", NULL,			0,		1}, /* 213 */
	{"epoll_ctl_old", NULL,			NOSYS_NULL,	0}, /* 214 */
	{"epoll_wait_old", NULL,		NOSYS_NULL,	0}, /* 215 */
	{"remap_file_pages", NULL,		NOSYS_NO_EQUIV,	0}, /* 216 */
	{"getdents64",	NULL,			0,		3}, /* 217 */
	{"set_tid_address", lx_set_tid_address, 0,		1}, /* 218 */
	{"restart_syscall", NULL,		NOSYS_NULL,	0}, /* 219 */
	{"semtimedop",	NULL,			0,		4}, /* 220 */
	{"fadvise64",	NULL,			0,		4}, /* 221 */
	{"timer_create", NULL,			0,		3}, /* 222 */
	{"timer_settime", NULL,			0,		4}, /* 223 */
	{"timer_gettime", NULL,			0,		2}, /* 224 */
	{"timer_getoverrun", NULL,		0,		1}, /* 225 */
	{"timer_delete", NULL,			0,		1}, /* 226 */
	{"clock_settime", NULL,			0,		2}, /* 227 */
	{"clock_gettime", NULL,			0,		2}, /* 228 */
	{"clock_getres", NULL,			0,		2}, /* 229 */
	{"clock_nanosleep", NULL,		0,		4}, /* 230 */
	{"exit_group",	NULL,			0,		1}, /* 231 */
	{"epoll_wait",	NULL,			0,		4}, /* 232 */
	{"epoll_ctl",	NULL,			0,		4}, /* 233 */
	{"tgkill",	lx_tgkill,		0,		3}, /* 234 */
	{"utimes",	NULL,			0,		2}, /* 235 */
	{"vserver",	NULL,			NOSYS_NULL,	0}, /* 236 */
	{"mbind",	NULL,			NOSYS_NULL,	0}, /* 237 */
	{"set_mempolicy", NULL,			NOSYS_NULL,	0}, /* 238 */
	{"get_mempolicy", NULL,			NOSYS_NULL,	0}, /* 239 */
	{"mq_open",	NULL,			NOSYS_NULL,	0}, /* 240 */
	{"mq_unlink",	NULL,			NOSYS_NULL,	0}, /* 241 */
	{"mq_timedsend", NULL,			NOSYS_NULL,	0}, /* 242 */
	{"mq_timedreceive", NULL,		NOSYS_NULL,	0}, /* 243 */
	{"mq_notify",	NULL,			NOSYS_NULL,	0}, /* 244 */
	{"mq_getsetattr", NULL,			NOSYS_NULL,	0}, /* 245 */
	{"kexec_load",	NULL,			NOSYS_NULL,	0}, /* 246 */
	{"waitid",	lx_waitid,		0,		4}, /* 247 */
	{"add_key",	NULL,			NOSYS_NULL,	0}, /* 248 */
	{"request_key",	NULL,			NOSYS_NULL,	0}, /* 249 */
	{"keyctl",	NULL,			NOSYS_NULL,	0}, /* 250 */
	{"ioprio_set",	NULL,			NOSYS_NULL,	0}, /* 251 */
	{"ioprio_get",	NULL,			NOSYS_NULL,	0}, /* 252 */
	{"inotify_init", NULL,			0,		0}, /* 253 */
	{"inotify_add_watch", NULL,		0,		3}, /* 254 */
	{"inotify_rm_watch", NULL,		0,		2}, /* 255 */
	{"migrate_pages", NULL,			NOSYS_NULL,	0}, /* 256 */
	{"openat",	NULL,			0,		4}, /* 257 */
	{"mkdirat",	NULL,			0,		3}, /* 258 */
	{"mknodat",	NULL,			0,		4}, /* 259 */
	{"fchownat",	NULL,			0,		5}, /* 260 */
	{"futimesat",	NULL,			0,		3}, /* 261 */
	{"fstatat64",	NULL,			0,		4}, /* 262 */
	{"unlinkat",	NULL,			0,		3}, /* 263 */
	{"renameat",	NULL,			0,		4}, /* 264 */
	{"linkat",	NULL,			0,		5}, /* 265 */
	{"symlinkat",	NULL,			0,		3}, /* 266 */
	{"readlinkat",	NULL,			0,		4}, /* 267 */
	{"fchmodat",	NULL,			0,		4}, /* 268 */
	{"faccessat",	NULL,			0,		4}, /* 269 */
	{"pselect6",	NULL,			0,		6}, /* 270 */
	{"ppoll",	NULL,			0,		5}, /* 271 */
	{"unshare",	NULL,			NOSYS_NULL,	0}, /* 272 */
	{"set_robust_list", NULL,		NOSYS_NULL,	0}, /* 273 */
	{"get_robust_list", NULL,		NOSYS_NULL,	0}, /* 274 */
	{"splice",	NULL,			NOSYS_NULL,	0}, /* 275 */
	{"tee",		NULL,			NOSYS_NULL,	0}, /* 276 */
	{"sync_file_range", NULL,		NOSYS_NULL,	0}, /* 277 */
	{"vmsplice",	NULL,			NOSYS_NULL,	0}, /* 278 */
	{"move_pages",	NULL,			NOSYS_NULL,	0}, /* 279 */
	{"utimensat",	NULL,			0,		4}, /* 280 */
	{"epoll_pwait",	NULL,			0,		5}, /* 281 */
	{"signalfd",	NULL,			NOSYS_NULL,	0}, /* 282 */
	{"timerfd_create", NULL,		NOSYS_NULL,	0}, /* 283 */
	{"eventfd",	NULL,			0,		1}, /* 284 */
	{"fallocate",	NULL,			NOSYS_NULL,	0}, /* 285 */
	{"timerfd_settime", NULL,		NOSYS_NULL,	0}, /* 286 */
	{"timerfd_gettime", NULL,		NOSYS_NULL,	0}, /* 287 */
	{"accept4",	NULL,			0,		4}, /* 288 */
	{"signalfd4",	NULL,			NOSYS_NULL,	0}, /* 289 */
	{"eventfd2",	NULL,			0,		2}, /* 290 */
	{"epoll_create1", NULL,			0,		1}, /* 291 */
	{"dup3",	NULL,			0,		3}, /* 292 */
	{"pipe2",	lx_pipe2,		0,		2}, /* 293 */
	{"inotify_init1", NULL,			0,		1}, /* 294 */
	{"preadv",	NULL,			NOSYS_NULL,	0}, /* 295 */
	{"pwritev",	NULL,			NOSYS_NULL,	0}, /* 296 */
	{"rt_tgsigqueueinfo", NULL, 		0,		4}, /* 297 */
	{"perf_event_open", NULL,		NOSYS_NULL,	0}, /* 298 */
	{"recvmmsg",	NULL,			NOSYS_NULL,	0}, /* 299 */
	{"fanotify_init", NULL,			NOSYS_NULL,	0}, /* 300 */
	{"fanotify_mark", NULL,			NOSYS_NULL,	0}, /* 301 */
	{"prlimit64",	NULL,			0,		4}, /* 302 */
	{"name_to_handle_at", NULL,		NOSYS_NULL,	0}, /* 303 */
	{"open_by_handle_at", NULL,		NOSYS_NULL,	0}, /* 304 */
	{"clock_adjtime", NULL,			NOSYS_NULL,	0}, /* 305 */
	{"syncfs",	NULL,			NOSYS_NULL,	0}, /* 306 */
	{"sendmmsg",	NULL,			NOSYS_NULL,	0}, /* 307 */
	{"setns",	NULL,			NOSYS_NULL,	0}, /* 309 */
	{"getcpu",	NULL,			0,		3}, /* 309 */
	{"process_vm_readv", NULL,		NOSYS_NULL,	0}, /* 310 */
	{"process_vm_writev", NULL,		NOSYS_NULL,	0}, /* 311 */
	{"kcmp",	NULL,			NOSYS_NULL,	0}, /* 312 */
	{"finit_module", NULL,			NOSYS_NULL,	0}, /* 313 */
	{"sched_setattr", NULL,			NOSYS_NULL,	0}, /* 314 */
	{"sched_getattr", NULL,			NOSYS_NULL,	0}, /* 315 */
	{"renameat2", NULL,			NOSYS_NULL,	0}, /* 316 */
	{"seccomp",	NULL,			NOSYS_NULL,	0}, /* 317 */
	{"getrandom",	NULL,			NOSYS_NULL,	0}, /* 318 */
	{"memfd_create", NULL,			NOSYS_NULL,	0}, /* 319 */
	{"kexec_file_load", NULL,		NOSYS_NULL,	0}, /* 320 */
	{"bpf",		NULL,			NOSYS_NULL,	0}, /* 321 */
	{"execveat",	NULL,			NOSYS_NULL,	0}, /* 322 */

	/* XXX TBD gap then x32 syscalls from 512 - 544 */
};
#endif
