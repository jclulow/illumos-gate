/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015, Joyent, Inc.
 */

static int
lx_signo(int native_signo)
{
	if (native_signo < 0 || native_signo >= NSIG) {
		return (-1);
	}

	return (stol_signo[native_signo]);
}

/*
 * Convert k_siginfo_t from waitid() into a status code for Linux waitpid(2).
 */
static int
lx_wstat(k_siginfo_t *ip)
{
	int stat = 0;

	switch (ip->si_code) {
	case CLD_EXITED:
		stat = ip->si_status << 8;
		break;
	case CLD_DUMPED:
		stat = lx_signo(ip->si_status) | WCOREFLG;
		break;
	case CLD_KILLED:
		stat = lx_signo(ip->si_status);
		break;
	case CLD_TRAPPED:
	case CLD_STOPPED:
		stat = stol_signo[status];
		assert(stat != -1);
		stat <<= 8;
		stat |= WSTOPFLG;
		break;
	case CLD_CONTINUED:
		stat = WCONTFLG;
		break;
	}

	return (stat);
}

pid_t
lx_wait4(pid_t pid, uintptr_t statusp, int options, uintptr_t rusagep)
{
	int error;
	int extra = 0;
	int native_opts = 0;
	int status;
	id_t id;
	idtype_t idtype;
	k_siginfo_t si;
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);

	/*
	 * Check options.
	 */
	if ((options & ~(LX_WNOHANG | LX_WUNTRACED | LX_WCONTINUED |
	    LX__WNOTHREAD | LX__WCLONE | LX__WALL)) != 0) {
		return (set_errno(EINVAL));
	}

	/*
	 * Convert Linux options to those for the native waitid().  The WEXITED
	 * option is implicit for Linux wait4() and waitpid().
	 */
	native_opts = WEXITED;
	if (options & LX_WNOHANG)
		native_opts |= WNOHANG;
	if (options & LX_WUNTRACED)
		native_opts |= WUNTRACED;
	if (options & LX_WCONTINUED)
		native_opts |= WCONTINUED;

	/*
	 * Store the extra options, for which there is no illumos analogue,
	 * in the brand-specific data.  They will be read from here by our
	 * waitid helper.
	 */
	lwpd->br_waitid_flags = options & (LX__WNOTHREAD | LX__WALL |
	    LX__WCLONE);

	/*
	 * While not listed as a valid return code, Linux's wait4(2) does,
	 * in fact, get an EFAULT if either the status pointer or rusage
	 * pointer is invalid. Since a failed waitpid should leave child
	 * process in a state where a future wait4(2) will succeed, we
	 * check them by copying out the values their buffers originally
	 * contained.  (We need to do this as a failed system call should
	 * never affect the contents of a passed buffer.)
	 *
	 * This will fail if the buffers in question are write-only.
	 */
	if (statusp != NULL &&
	    (copyin((void *)statusp, &status, sizeof (status)) != 0 ||
	    copyout(&status, (void *)statusp, sizeof (status)) != 0)) {
		return (EFAULT);
	}

	/*
	 * Determine ID filter type.
	 */
	if (pid == -1) {
		/*
		 * Any process (or thread) will do:
		 */
		idtype = P_ALL;
		id = 0;
	} else if (pid < 1) {
		/*
		 * A specific progress group ID.
		 */
		idtype = P_PGID;
		id = -pid;
	} else if (pid == 0) {
		/*
		 * Match only processes in the current process group:
		 */
		idtype = P_PGID;
		mutex_enter(&pidlock);
		id = curproc->p_pgrp;
		mutex_exit(&pidlock);
	} else {
		/*
		 * A specific process (or thread) ID.
		 */
		idtype = P_PID;
		id = pid;
	}

	/*
	 * XXX call waitid(), I guess.
	 */
	if ((error = waitid(idtype, id, &si, native_opts)) != 0) {
		return (set_errno(error));
	}
}

long
lx_waitpid(pid_t pid, uintptr_t statusp, int options, uintptr_t rusagep)
{
	return (lx_wait4(pid, statusp, options, NULL));
}

long
lx_waitid(idtype_t idtype, id_t id, uintptr_t infop, int options)
{
	int rval;
	siginfo_t s_info = { 0 };

	/*
	 * waitid(2) requires at least one of these flags to be set:
	 */
	if (((options) & (LX_WEXITED | LX_WSTOPPED | LX_WCONTINUED)) == 0) {
		return (set_errno(EINVAL));
	}
}
