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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2015, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/segments.h>
#include <sys/lx_types.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_poll.h>
#include <sys/lx_signal.h>
#include <sys/lx_sigstack.h>
#include <sys/lx_syscall.h>
#include <sys/lx_thread.h>
#include <sys/syscall.h>
#include <lx_provider_impl.h>
#include <sys/stack.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <rctl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <thread.h>
#include <ucontext.h>
#include <unistd.h>
#include <stdio.h>
#include <libintl.h>
#include <ieeefp.h>

#if defined(_ILP32)
extern int pselect_large_fdset(int nfds, fd_set *in0, fd_set *out0, fd_set *ex0,
	const timespec_t *tsp, const sigset_t *sp);
#endif

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

/*
 * Delivering signals to a Linux process is complicated by differences in
 * signal numbering, stack structure and contents, and the action taken when a
 * signal handler exits.  In addition, many signal-related structures, such as
 * sigset_ts, vary between Illumos and Linux.
 *
 * To support user-level signal handlers, the brand uses a double layer of
 * indirection to process and deliver signals to branded threads.
 *
 * When a Linux process sends a signal using the kill(2) system call, we must
 * translate the signal into the Illumos equivalent before handing control off
 * to the standard signalling mechanism.  When a signal is delivered to a Linux
 * process, we translate the signal number from Illumos to back to Linux.
 * Translating signals both at generation and delivery time ensures both that
 * Illumos signals are sent properly to Linux applications and that signals'
 * default behavior works as expected.
 *
 * In a normal Illumos process, signal delivery is interposed on for any thread
 * registering a signal handler by libc. Libc needs to do various bits of magic
 * to provide thread-safe critical regions, so it registers its own handler,
 * named sigacthandler(), using the sigaction(2) system call. When a signal is
 * received, sigacthandler() is called, and after some processing, libc turns
 * around and calls the user's signal handler via a routine named
 * call_user_handler().
 *
 * Adding a Linux branded thread to the mix complicates things somewhat.
 *
 * First (for 32-bit code), when a thread receives a signal, it may be running
 * with a Linux value in the x86 %gs segment register as opposed to the value
 * Illumos threads expect; if control were passed directly to Illumos code,
 * such as libc's sigacthandler(), that code would experience a segmentation
 * fault the first time it tried to dereference a memory location using %gs.
 *
 * For 64-bit code the %gs is usually 0 for both native and Linux code and the
 * thread pointer for both Illumos and Linux libc is referenced off the %fsbase
 * register, as per the AMD64 ABI. When a thread receives a signal, it may be
 * running with the Linux value in the x86 %fsbase register as opposed to the
 * value Illumos libc expects. Switching the %fsbase value is handled in the
 * kernel module at the same time as we switch the syscall mode flag. We track
 * the syscall mode flag in the kernel using the per-lwp br_scms integer so we
 * can save/restore the correct mode at the end of the signal handling. The
 * flag value is saved/restored in the per-thread br_scms variable which is
 * used like a stack to push/pop the flag bit as we take signals and return.
 *
 * Second, the signal number translation referenced above must take place.
 * Further, for 32-bit code, as was the case with Illumos libc, before the
 * Linux signal handler is called, the value of the %gs segment register MUST
 * be restored to the value Linux code expects.
 *
 * This need to translate signal numbers (and manipulate the %gs register)
 * means that with standard Illumos libc, following a signal from generation to
 * delivery looks something like:
 *
 * 	kernel ->
 *	    sigacthandler() ->
 *		call_user_handler() ->
 *		    user signal handler
 *
 * but for the brand's Linux threads, this would look like:
 *
 *	kernel ->
 *	    lx_sigacthandler() ->
 *		sigacthandler() ->
 *		    call_user_handler() ->
 *			lx_call_user_handler() ->
 *                          lx_sigdeliver() JMP to
 *                              Linux user signal handler
 *
 * The new addtions are:
 *
 * 	lx_sigacthandler
 *	================
 *	This routine is responsible for setting the %gs segment register to the
 *	value 32-bit Illumos code expects (it does nothing in 64-bit code) and
 *	jumping to Illumos' libc signal interposition handler, sigacthandler().
 *
 * 	lx_call_user_handler
 *	====================
 *	This routine is responsible for translating Illumos signal numbers to
 *	their Linux equivalents, building a Linux signal stack based on the
 * 	information Illumos has provided, and passing the stack to the
 *	registered Linux signal handler. It is, in effect, the Linux thread
 *	equivalent to libc's call_user_handler().
 *
 * Installing lx_sigacthandler() is a bit tricky, as normally libc's
 * sigacthandler() routine is hidden from user programs. To facilitate this, a
 * libc private function is used; setsigacthandler():
 *
 *	void setsigacthandler(void (*new_handler)(int, siginfo_t *, void *),
 *	    void (**old_handler)(int, siginfo_t *, void *)
 *	    int (*brsetctxt)(const ucontext_t *))
 *
 * The routine works by modifying the per-thread data structure (uberdata) in
 * libc that keeps track of the address of its own interposition handler with
 * the address passed in; the old handler's address is returned in the pointer
 * pointed to by the second argument, if it is non-NULL, mimicking the behavior
 * of sigaction() itself. In a similar way, this function can also set a
 * replacement handler for the libc __setcontext call which is made by libc's
 * setcontext() when returning from a signal handler. Using this we can hook
 * in to managing the syscall mode flag for 64-bit code when returning to the
 * interrupted code. Once setsigacthandler() has been executed, all future
 * branded threads this thread may create will automatically have the proper
 * interposition handler(s) invoked as the result of a normal sigaction() call.
 *
 * Note that none of this interposition is necessary unless a Linux thread
 * registers a user signal handler, as the default action for all signals is the
 * same between Illumos and Linux save for one signal, SIGPWR.  For this reason,
 * the brand ALWAYS installs its own internal signal handler for SIGPWR that
 * translates the action to the Linux default, to terminate the process.
 * (Illumos' default action is to ignore SIGPWR.)
 *
 * It is also important to note that when signals are not translated, the brand
 * relies upon code interposing upon the wait(2) system call to translate
 * signals to their proper values for any Linux threads retrieving the status
 * of others.  So while the Illumos signal number for a particular signal is set
 * in a process' data structures (and would be returned as the result of say,
 * WTERMSIG()), the brand's interposiiton upon wait(2) is responsible for
 * translating the value WTERMSIG() would return from a Illumos signal number
 * to the appropriate Linux value.
 *
 * lx_call_user_handler() calls lx_sigdeliver with a helper function (typically
 * lx_build_signal_frame) which builds a stack frame for the 32-bit Linux
 * signal handler, or populates a local (on the stack) structure for the 64-bit
 * Linux signal handler, then jmp's into the handler. The stack at that time
 * looks like this:
 *
 * 	=================================================
 * |	| LX_SIGRT_MAGIC				|
 * | 	=================================================
 * |	| Linux signal frame (32-bit) or local data	|
 * V	| (64-bit) built by stack_builder()		|
 * 	=================================================
 *
 * The process of returning to an interrupted thread of execution from a user
 * signal handler is entirely different between Illumos and Linux.  While
 * Illumos generally expects to set the context to the interrupted one on a
 * normal return from a signal handler, in the normal case Linux instead calls
 * code that calls a specific Linux system call, rt_sigreturn(2) (or it also
 * can call sigreturn(2) in 32-bit code).  Thus when a Linux signal handler
 * completes execution, instead of returning through what would in libc be a
 * call to setcontext(2), the rt_sigreturn(2) Linux system call is responsible
 * for accomplishing much the same thing. It's for this reason that the stack
 * frame we build has the lx_(rt_)sigreturn_tramp code on the top of the
 * stack.
 *
 * The lx_rt_sigreturn() function will handle the syscall, do its cleanup,
 * then return to the libc signal handling code (call_user_handler) so that
 * libc can use setcontext() to get back to the point where things were
 * interrupted. However, for the 64-bit case, due to the syscall mode switching,
 * we cannot simply let the libc setcontext() take us back because we may also
 * have to switch the syscall mode back to Linux (it depends on where we were
 * when we took the signal). For the 64-bit case we used setsigacthandler()
 * to setup a libc replacement function on __setcontext(). This is the
 * lx_setcontext() function. This function uses a brand call (B_SIGNAL_RETURN)
 * which combines the syscall mode switching and setcontext handling in the lx
 * kernel module.
 * XXX NO WE DONT
 *
 * An additional oddity in the signal return code is that in the stack builder
 * function we push some x86 code onto the bottom of the stack that looks like
 * it invokes the Linux (rt)_sigreturn syscall. This is needed by gdb to
 * tell that it's in a signal handler. The code looks like this:
 *
 *	32-bit					64-bit
 *	--------------------------------	-----------------------------
 *	mov LX_SYS_rt_sigreturn, %eax		movq LX_SYS_rt_sigreturn, %rax
 *	int $0x80				syscall
 *
 * We also use these same functions (lx_rt_sigreturn_tramp or
 * lx_sigreturn_tramp) to actually return from the signal handler.
 *
 * (Note that this trampoline code actually lives in a proper executable segment
 * and not on the stack, but gdb checks for the exact code sequence of the
 * trampoline code on the stack to determine whether it is in a signal stack
 * frame or not.  Really.)
 *
 * When the 32-bit Linux user signal handler is eventually called, the stack
 * frame looks like this (in the case of a "modern" signal stack; see the
 * lx_sigstack structure definition):
 *
 *	=========================================================
 * |	| Trampoline code (marker for gdb, not really executed)	|
 * |	=========================================================
 * |	| Linux struct _fpstate					|
 * |	=========================================================
 * V	| Linux ucontext_t					| <--+
 *	=========================================================    |
 *	| Linux siginfo_t					| <--|-----+
 *	=========================================================    |     |
 *	| Pointer to Linux ucontext_t (or NULL)	(sigaction arg2)| ---+     |
 *	=========================================================          |
 *	| Pointer to Linux siginfo_t (or NULL)  (sigaction arg1)| ---------+
 *	=========================================================
 *	| Linux signal number                   (sigaction arg0)|
 *	=========================================================
 *	| Pointer to signal return code (trampoline code)	|
 *	=========================================================
 *
 * The 64-bit stack-local data looks like this:
 *
 *	=========================================================
 * |	| Trampoline code (marker for gdb, not really executed)	|
 * |	=========================================================
 * |	| Linux struct _fpstate					|
 * |	=========================================================
 * V	| Linux ucontext_t					| %rdx arg2
 *	=========================================================
 *	| Linux siginfo_t					| %rsi arg1
 *	=========================================================
 *	| Pointer to signal return code (trampoline code)	|
 *	=========================================================
 *
 * As usual in 64-bit code, %rdi is arg0 which is the signal number.
 *
 * As mentioned above, the brand intercepts the Linux (rt_)sigreturn(2) system
 * call. This turns into some stack cleanup and a call to lx_sigreturn_tolibc()
 * which returns through the libc call stack that Illumos expects, with the
 * caveat that 64-bit code combines the __setcontext and syscall mode switch
 * via a brand call. This returns the thread executing the code back to the
 * location originally interrupted by receipt of the signal.
 */

typedef struct lx_sigdeliver_frame {
	uintptr_t lxsdf_magic;
	ucontext_t *lxsdf_retucp;
	ucontext_t *lxsdf_sigucp;
} lx_sigdeliver_frame_t;

struct lx_oldsigstack {
	void (*retaddr)();	/* address of real lx_sigreturn code */
	int sig;		/* signal number */
	lx_sigcontext_t sigc;	/* saved user context */
	lx_fpstate_t fpstate;	/* saved FP state */
	int sig_extra;		/* signal mask for signals [32 .. NSIG - 1] */
	char trampoline[8];	/* code for trampoline to lx_sigreturn() */
};

/*
 * The lx_sighandlers structure needs to be a global due to the semantics of
 * clone().
 *
 * If CLONE_SIGHAND is set, the calling process and child share signal
 * handlers, and if either calls sigaction(2) it should change the behavior
 * in the other thread.  Each thread does, however, have its own signal mask
 * and set of pending signals.
 *
 * If CLONE_SIGHAND is not set, the child process should inherit a copy of
 * the signal handlers at the time of the clone() but later calls to
 * sigaction(2) should only affect the individual thread calling it.
 *
 * This maps perfectly to a thr_create(3C) thread semantic in the first
 * case and a fork(2)-type semantic in the second case.  By making
 * lx_sighandlers global, we automatically get the correct behavior.
 */
static lx_sighandlers_t lx_sighandlers;

static void lx_sigdeliver(int, siginfo_t *, ucontext_t *, size_t, void (*)(),
    void (*)(), struct lx_sigaction *);

/*
 * Cache result of process.max-file-descriptor to avoid calling getrctl()
 * for each lx_ppoll().
 */
static rlim_t maxfd = 0;

/*
 * stol_stack() and ltos_stack() convert between Illumos and Linux stack_t
 * structures.
 *
 * These routines are needed because although the two structures have the same
 * contents, their contents are declared in a different order, so the content
 * of the structures cannot be copied with a simple bcopy().
 */
static void
stol_stack(stack_t *fr, lx_stack_t *to)
{
	to->ss_sp = fr->ss_sp;
	to->ss_flags = fr->ss_flags;
	to->ss_size = fr->ss_size;
}

static void
ltos_stack(lx_stack_t *fr, stack_t *to)
{
	to->ss_sp = fr->ss_sp;
	to->ss_flags = fr->ss_flags;
	to->ss_size = fr->ss_size;
}

static int
ltos_sigset(lx_sigset_t *lx_sigsetp, sigset_t *s_sigsetp)
{
	lx_sigset_t l;
	int lx_sig, sig;

	if (uucopy(lx_sigsetp, &l, sizeof (lx_sigset_t)) != 0)
		return (-errno);

	(void) sigemptyset(s_sigsetp);

	for (lx_sig = 1; lx_sig <= LX_NSIG; lx_sig++) {
		if (lx_sigismember(&l, lx_sig) &&
		    ((sig = ltos_signo[lx_sig]) > 0))
			(void) sigaddset(s_sigsetp, sig);
	}

	return (0);
}

static int
stol_sigset(sigset_t *s_sigsetp, lx_sigset_t *lx_sigsetp)
{
	lx_sigset_t l;
	int sig, lx_sig;

	bzero(&l, sizeof (lx_sigset_t));

	for (sig = 1; sig < NSIG; sig++) {
		if (sigismember(s_sigsetp, sig) &&
		    ((lx_sig = stol_signo[sig]) > 0))
			lx_sigaddset(&l, lx_sig);
	}

	return ((uucopy(&l, lx_sigsetp, sizeof (lx_sigset_t)) != 0)
	    ? -errno : 0);
}

#if defined(_ILP32)
static int
ltos_osigset(lx_osigset_t *lx_osigsetp, sigset_t *s_sigsetp)
{
	lx_osigset_t lo;
	int lx_sig, sig;

	if (uucopy(lx_osigsetp, &lo, sizeof (lx_osigset_t)) != 0)
		return (-errno);

	(void) sigemptyset(s_sigsetp);

	for (lx_sig = 1; lx_sig <= OSIGSET_NBITS; lx_sig++)
		if ((lo & OSIGSET_BITSET(lx_sig)) &&
		    ((sig = ltos_signo[lx_sig]) > 0))
			(void) sigaddset(s_sigsetp, sig);

	return (0);
}

static int
stol_osigset(sigset_t *s_sigsetp, lx_osigset_t *lx_osigsetp)
{
	lx_osigset_t lo = 0;
	int lx_sig, sig;

	/*
	 * Note that an lx_osigset_t can only represent the signals from
	 * [1 .. OSIGSET_NBITS], so even though a signal may be present in the
	 * Illumos sigset_t, it may not be representable as a bit in the
	 * lx_osigset_t.
	 */
	for (sig = 1; sig < NSIG; sig++)
		if (sigismember(s_sigsetp, sig) &&
		    ((lx_sig = stol_signo[sig]) > 0) &&
		    (lx_sig <= OSIGSET_NBITS))
			lo |= OSIGSET_BITSET(lx_sig);

	return ((uucopy(&lo, lx_osigsetp, sizeof (lx_osigset_t)) != 0)
	    ? -errno : 0);
}
#endif

static int
stol_sigcode(int si_code)
{
	switch (si_code) {
		case SI_USER:
			return (LX_SI_USER);
		case SI_LWP:
			return (LX_SI_TKILL);
		case SI_QUEUE:
			return (LX_SI_QUEUE);
		case SI_TIMER:
			return (LX_SI_TIMER);
		case SI_ASYNCIO:
			return (LX_SI_ASYNCIO);
		case SI_MESGQ:
			return (LX_SI_MESGQ);
		default:
			return (si_code);
	}
}

static int
ltos_sigcode(int si_code)
{
	switch (si_code) {
		case LX_SI_USER:
			return (SI_USER);
		case LX_SI_TKILL:
			return (SI_LWP);
		case LX_SI_QUEUE:
			return (SI_QUEUE);
		case LX_SI_TIMER:
			return (SI_TIMER);
		case LX_SI_ASYNCIO:
			return (SI_ASYNCIO);
		case LX_SI_MESGQ:
			return (SI_MESGQ);
		default:
			return (LX_SI_CODE_NOT_EXIST);
	}
}

int
stol_siginfo(siginfo_t *siginfop, lx_siginfo_t *lx_siginfop)
{
	int ret = 0;
	lx_siginfo_t lx_siginfo;

	bzero(&lx_siginfo, sizeof (*lx_siginfop));

	if ((lx_siginfo.lsi_signo = stol_signo[siginfop->si_signo]) <= 0) {
		/*
		 * Depending on the caller we may still need to get a usable
		 * converted siginfo struct.
		 */
		lx_siginfo.lsi_signo = LX_SIGKILL;
		errno = EINVAL;
		ret = -1;
	}

	lx_siginfo.lsi_code = stol_sigcode(siginfop->si_code);
	lx_siginfo.lsi_errno = siginfop->si_errno;

	switch (lx_siginfo.lsi_signo) {
		/*
		 * Semantics ARE defined for SIGKILL, but since
		 * we can't catch it, we can't translate it. :-(
		 */
		case LX_SIGPOLL:
			lx_siginfo.lsi_band = siginfop->si_band;
			lx_siginfo.lsi_fd = siginfop->si_fd;
			break;

		case LX_SIGCHLD:
			lx_siginfo.lsi_pid = siginfop->si_pid;
			lx_siginfo.lsi_status = siginfop->si_status;
			lx_siginfo.lsi_utime = siginfop->si_utime;
			lx_siginfo.lsi_stime = siginfop->si_stime;
			break;

		case LX_SIGILL:
		case LX_SIGBUS:
		case LX_SIGFPE:
		case LX_SIGSEGV:
			lx_siginfo.lsi_addr = siginfop->si_addr;
			break;

		default:
			lx_siginfo.lsi_pid = siginfop->si_pid;
			lx_siginfo.lsi_uid =
			    LX_UID32_TO_UID16(siginfop->si_uid);
			break;
	}

	if (uucopy(&lx_siginfo, lx_siginfop, sizeof (lx_siginfo_t)) != 0)
		return (-errno);
	return ((ret != 0) ? -errno : 0);
}

static void
stol_fpstate(fpregset_t *fpr, lx_fpstate_t *lfpr)
{
	size_t copy_len;

#if defined(_LP64)
	/*
	 * The 64-bit Illumos struct fpregset_t and lx_fpstate_t are identical
	 * so just bcopy() those entries (see usr/src/uts/intel/sys/regset.h
	 * for __amd64's struct fpu).
	 */
	copy_len = sizeof (fpr->fp_reg_set.fpchip_state);
	bcopy(fpr, lfpr, copy_len);

#else /* is _ILP32 */
	struct _fpstate *fpsp = (struct _fpstate *)fpr;

	/*
	 * The Illumos struct _fpstate and lx_fpstate_t are identical from the
	 * beginning of the structure to the lx_fpstate_t "magic" field, so
	 * just bcopy() those entries.
	 */
	copy_len = (size_t)&(((lx_fpstate_t *)0)->magic);
	bcopy(fpsp, lfpr, copy_len);

	/*
	 * These fields are all only significant for the first 16 bits.
	 */
	lfpr->cw &= 0xffff;		/* x87 control word */
	lfpr->tag &= 0xffff;		/* x87 tag word */
	lfpr->cssel &= 0xffff;		/* cs selector */
	lfpr->datasel &= 0xffff;	/* ds selector */

	/*
	 * Linux wants the x87 status word field to contain the value of the
	 * x87 saved exception status word.
	 */
	lfpr->sw = lfpr->status & 0xffff;	/* x87 status word */

	lfpr->mxcsr = fpsp->mxcsr;

	if (fpsp->mxcsr != 0) {
		/*
		 * Linux uses the "magic" field to denote whether the XMM
		 * registers contain legal data or not.  Since we can't get to
		 * %cr4 from userland to check the status of the OSFXSR bit,
		 * check the mxcsr field to see if it's 0, which it should
		 * never be on a system with the OXFXSR bit enabled.
		 */
		lfpr->magic = LX_X86_FXSR_MAGIC;
		bcopy(fpsp->xmm, lfpr->_xmm, sizeof (lfpr->_xmm));
	} else {
		lfpr->magic = LX_X86_FXSR_NONE;
	}
#endif
}

static void
ltos_fpstate(lx_fpstate_t *lfpr, fpregset_t *fpr)
{
	size_t copy_len;

#if defined(_LP64)
	/*
	 * The 64-bit Illumos struct fpregset_t and lx_fpstate_t are identical
	 * so just bcopy() those entries (see usr/src/uts/intel/sys/regset.h
	 * for __amd64's struct fpu).
	 */
	copy_len = sizeof (fpr->fp_reg_set.fpchip_state);
	bcopy(lfpr, fpr, copy_len);

#else /* is _ILP32 */
	struct _fpstate *fpsp = (struct _fpstate *)fpr;

	/*
	 * The lx_fpstate_t and Illumos struct _fpstate are identical from the
	 * beginning of the structure to the struct _fpstate "mxcsr" field, so
	 * just bcopy() those entries.
	 *
	 * Note that we do NOT have to propogate changes the user may have made
	 * to the "status" word back to the "sw" word, unlike the way we have
	 * to deal with processing the ESP and UESP register values on return
	 * from a signal handler.
	 */
	copy_len = (size_t)&(((struct _fpstate *)0)->mxcsr);
	bcopy(lfpr, fpsp, copy_len);

	/*
	 * These fields are all only significant for the first 16 bits.
	 */
	fpsp->cw &= 0xffff;		/* x87 control word */
	fpsp->sw &= 0xffff;		/* x87 status word */
	fpsp->tag &= 0xffff;		/* x87 tag word */
	fpsp->cssel &= 0xffff;		/* cs selector */
	fpsp->datasel &= 0xffff;	/* ds selector */
	fpsp->status &= 0xffff;		/* saved status */

	fpsp->mxcsr = lfpr->mxcsr;

	if (lfpr->magic == LX_X86_FXSR_MAGIC)
		bcopy(lfpr->_xmm, fpsp->xmm, sizeof (fpsp->xmm));
#endif
}

/*
 * We do not use the system sigaltstack() infrastructure as that would conflict
 * with our handling of both system call emulation and native signals on the
 * native stack.  Instead, we track the Linux stack structure in our
 * thread-specific data.  This function is modeled on the behaviour of the
 * native sigaltstack system call handler.
 */
long
lx_sigaltstack(uintptr_t ssp, uintptr_t oss)
{
	lx_tsd_t *lxtsd = lx_get_tsd();
	lx_stack_t ss;

	if (ssp != NULL) {
		if (lxtsd->lxtsd_sigaltstack.ss_flags & LX_SS_ONSTACK) {
			/*
			 * If we are currently using the installed alternate
			 * stack for signal handling, the user may not modify
			 * the stack for this thread.
			 */
			return (-EPERM);
		}

		if (uucopy((void *)ssp, &ss, sizeof (ss)) != 0) {
			return (-EFAULT);
		}

		if (ss.ss_flags & ~LX_SS_DISABLE) {
			/*
			 * The user may not specify a value for flags other
			 * than 0 or SS_DISABLE.
			 */
			return (-EINVAL);
		}

		if (!(ss.ss_flags & LX_SS_DISABLE) && ss.ss_size <
		    LX_MINSIGSTKSZ) {
			return (-ENOMEM);
		}
	}

	if (oss != NULL) {
		/*
		 * User provided old and new stack_t pointers may point to
		 * the same location.  Copy out before we modify.
		 */
		if (uucopy(&lxtsd->lxtsd_sigaltstack, (void *)oss,
		    sizeof (lxtsd->lxtsd_sigaltstack)) != 0) {
			return (-EFAULT);
		}
	}

	if (ssp != NULL) {
		lxtsd->lxtsd_sigaltstack = ss;
	}

	return (0);
}

#if defined(_ILP32)
/*
 * The following routines are needed because sigset_ts and siginfo_ts are
 * different in format between Linux and Illumos.
 *
 * Note that there are two different lx_sigset structures, lx_sigset_ts and
 * lx_osigset_ts:
 *
 *    + An lx_sigset_t is the equivalent of a Illumos sigset_t and supports
 *	more than 32 signals.
 *
 *    + An lx_osigset_t is simply a uint32_t, so it by definition only supports
 *	32 signals.
 *
 * When there are two versions of a routine, one prefixed with lx_rt_ and
 * one prefixed with lx_ alone, in GENERAL the lx_rt_ routines deal with
 * lx_sigset_ts while the lx_ routines deal with lx_osigset_ts.  Unfortunately,
 * this is not always the case (e.g. lx_sigreturn() vs. lx_rt_sigreturn())
 */
long
lx_sigpending(uintptr_t sigpend)
{
	sigset_t sigpendset;

	if (sigpending(&sigpendset) != 0)
		return (-errno);

	return (stol_osigset(&sigpendset, (lx_osigset_t *)sigpend));
}
#endif

long
lx_rt_sigpending(uintptr_t sigpend, uintptr_t setsize)
{
	sigset_t sigpendset;

	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	if (sigpending(&sigpendset) != 0)
		return (-errno);

	return (stol_sigset(&sigpendset, (lx_sigset_t *)sigpend));
}

/*
 * Create a common routine to encapsulate all of the sigprocmask code,
 * as the only difference between lx_sigprocmask() and lx_rt_sigprocmask()
 * is the usage of lx_osigset_ts vs. lx_sigset_ts, as toggled in the code by
 * the setting of the "sigset_type" flag.
 */
static int
lx_sigprocmask_common(uintptr_t how, uintptr_t l_setp, uintptr_t l_osetp,
    uintptr_t sigset_type)
{
	int err = 0;
	sigset_t set, oset;
	sigset_t *s_setp = NULL;
	sigset_t *s_osetp;

	if (l_setp) {
		switch (how) {
			case LX_SIG_BLOCK:
				how = SIG_BLOCK;
				break;

			case LX_SIG_UNBLOCK:
				how = SIG_UNBLOCK;
				break;

			case LX_SIG_SETMASK:
				how = SIG_SETMASK;
				break;

			default:
				return (-EINVAL);
		}

		s_setp = &set;

		/* Only 32-bit code passes other than USE_SIGSET */
		if (sigset_type == USE_SIGSET)
			err = ltos_sigset((lx_sigset_t *)l_setp, s_setp);
#if defined(_ILP32)
		else
			err = ltos_osigset((lx_osigset_t *)l_setp, s_setp);
#endif

		if (err != 0)
			return (err);
	}

	s_osetp = (l_osetp ? &oset : NULL);

	/*
	 * In a multithreaded environment, a call to sigprocmask(2) should
	 * only affect the current thread's signal mask so we don't need to
	 * explicitly call thr_sigsetmask(3C) here.
	 */
	if (sigprocmask(how, s_setp, s_osetp) != 0)
		return (-errno);

	if (l_osetp) {
		if (sigset_type == USE_SIGSET)
			err = stol_sigset(s_osetp, (lx_sigset_t *)l_osetp);
#if defined(_ILP32)
		else
			err = stol_osigset(s_osetp, (lx_osigset_t *)l_osetp);
#endif

		if (err != 0) {
			/*
			 * Encountered a fault while writing to the old signal
			 * mask buffer, so unwind the signal mask change made
			 * above.
			 */
			(void) sigprocmask(how, s_osetp, (sigset_t *)NULL);
			return (err);
		}
	}

	return (0);
}

#if defined(_ILP32)
long
lx_sigprocmask(uintptr_t how, uintptr_t setp, uintptr_t osetp)
{
	return (lx_sigprocmask_common(how, setp, osetp, USE_OSIGSET));
}
#endif

long
lx_rt_sigprocmask(uintptr_t how, uintptr_t setp, uintptr_t osetp,
    uintptr_t setsize)
{
	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	return (lx_sigprocmask_common(how, setp, osetp, USE_SIGSET));
}

#if defined(_ILP32)
long
lx_sigsuspend(uintptr_t set)
{
	sigset_t s_set;

	if (ltos_osigset((lx_osigset_t *)set, &s_set) != 0)
		return (-errno);

	return ((sigsuspend(&s_set) == -1) ? -errno : 0);
}
#endif

long
lx_rt_sigsuspend(uintptr_t set, uintptr_t setsize)
{
	sigset_t s_set;

	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	if (ltos_sigset((lx_sigset_t *)set, &s_set) != 0)
		return (-errno);

	return ((sigsuspend(&s_set) == -1) ? -errno : 0);
}

long
lx_rt_sigwaitinfo(uintptr_t set, uintptr_t sinfo, uintptr_t setsize)
{
	sigset_t s_set;
	siginfo_t s_sinfo, *s_sinfop;
	int rc;

	lx_sigset_t *setp = (lx_sigset_t *)set;
	lx_siginfo_t *sinfop = (lx_siginfo_t *)sinfo;

	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	if (ltos_sigset(setp, &s_set) != 0)
		return (-errno);

	s_sinfop = (sinfop == NULL) ? NULL : &s_sinfo;

	if ((rc = sigwaitinfo(&s_set, s_sinfop)) == -1)
		return (-errno);

	if (s_sinfop == NULL)
		return (stol_signo[rc]);

	return ((stol_siginfo(s_sinfop, sinfop) != 0)
	    ? -errno : stol_signo[rc]);
}

long
lx_rt_sigtimedwait(uintptr_t set, uintptr_t sinfo, uintptr_t toutp,
    uintptr_t setsize)
{
	sigset_t s_set;
	siginfo_t s_sinfo, *s_sinfop;
	int rc;

	lx_sigset_t *setp = (lx_sigset_t *)set;
	lx_siginfo_t *sinfop = (lx_siginfo_t *)sinfo;

	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	if (ltos_sigset(setp, &s_set) != 0)
		return (-errno);

	s_sinfop = (sinfop == NULL) ? NULL : &s_sinfo;

	/*
	 * "If timeout is the NULL pointer, the behavior is unspecified."
	 * Match what LTP expects.
	 */
	if ((rc = sigtimedwait(&s_set, s_sinfop,
	    (struct timespec *)toutp)) == -1)
		return (toutp == NULL ? -EINTR : -errno);

	if (s_sinfop == NULL)
		return (stol_signo[rc]);

	return ((stol_siginfo(s_sinfop, sinfop) != 0)
	    ? -errno : stol_signo[rc]);
}

#if defined(_ILP32)
/*
 * Intercept the Linux sigreturn() syscall to turn it into the return through
 * the libc call stack that Illumos expects.
 *
 * When control returns to libc's call_user_handler() routine, a setcontext(2)
 * will be done that returns thread execution to the point originally
 * interrupted by receipt of the signal.
 *
 * This is only used by 32-bit code.
 */
long
lx_sigreturn(void)
{
	lx_sigdeliver_frame_t *lxsdf;
	struct lx_oldsigstack *lx_ossp;
	lx_sigset_t lx_sigset;
	ucontext_t *ucp;
	ucontext_t *sigucp;
	uintptr_t sp;

	ucp = lx_syscall_regs();

	/*
	 * NOTE:  The sp saved in the context is eight bytes off of where we
	 *	  need it to be (either due to trampoline or the copying of
	 *	  sp = uesp, not clear which).
	 */
	sp = (uintptr_t)LX_REG(ucp, REG_SP) - 8;

	/*
	 * At this point, the stack pointer should point to the struct
	 * lx_oldsigstack that lx_build_old_signal_frame() constructed and
	 * placed on the stack.  We need to reference it a bit later, so
	 * save a pointer to it before incrementing our copy of the sp.
	 */
	lx_ossp = (struct lx_oldsigstack *)sp;
	sp += SA(sizeof (struct lx_oldsigstack));


	/*
	 * lx_sigdeliver() pushes a lx_sigdeliver_frame_t onto the stack
	 * before it creates the struct lx_oldsigstack.
	 *
	 * If we do not find it here, the stack has been corrupted and we
	 * need to kill ourselves.
	 */
	lxsdf = (lx_sigdeliver_frame_t *)sp;
	lx_debug("lx_sigreturn: reading lx_sigdeliver_frame_t @ %p\n",
	    lxsdf);
	lx_debug("lx_sigreturn: lxsdf: magic %p retucp %p sigucp %p\n",
	    lxsdf->lxsdf_magic, lxsdf->lxsdf_retucp, lxsdf->lxsdf_sigucp);
	if (lxsdf->lxsdf_magic != LX_SIGRT_MAGIC) {
		lx_err_fatal("sp @ 0x%p, expected 0x%x, found 0x%x!",
		    sp, LX_SIGRT_MAGIC, lxsdf->lxsdf_magic);
	}

	LX_SIGNAL_DELIVERY_FRAME_FOUND(lxsdf);

	/*
	 * We need to copy machine registers the Linux signal handler may have
	 * modified back to the Illumos ucontext_t.
	 */
	sigucp = lxsdf->lxsdf_sigucp;

	/*
	 * General registers copy across as-is, except Linux expects that
	 * changes made to uc_mcontext.gregs[ESP] will be reflected when the
	 * interrupted thread resumes execution after the signal handler. To
	 * emulate this behavior, we must modify uc_mcontext.gregs[UESP] to
	 * match uc_mcontext.gregs[ESP] as Illumos will restore the UESP
	 * value to ESP.
	 */
	lx_ossp->sigc.sc_esp_at_signal = lx_ossp->sigc.sc_esp;
	bcopy(&lx_ossp->sigc, &sigucp->uc_mcontext, sizeof (gregset_t));

	/* copy back FP regs if present */
	if (lx_ossp->sigc.sc_fpstate != NULL)
		ltos_fpstate(&lx_ossp->fpstate, &sigucp->uc_mcontext.fpregs);

	/* convert Linux signal mask back to its Illumos equivalent */
	bzero(&lx_sigset, sizeof (lx_sigset_t));
	lx_sigset.__bits[0] = lx_ossp->sigc.sc_mask;
	lx_sigset.__bits[1] = lx_ossp->sig_extra;
	(void) ltos_sigset(&lx_sigset, &sigucp->uc_sigmask);

	/*
	 * For signal mask handling to be done properly, this call needs to
	 * return to the libc routine that originally called the signal handler
	 * rather than directly set the context back to the place the signal
	 * interrupted execution as the original Linux code would do.
	 */
	lx_debug("lx_sigreturn: calling setcontext; retucp %p flags %lx "
	    "link %p\n", lxsdf->lxsdf_retucp, lxsdf->lxsdf_retucp->uc_flags,
	    lxsdf->lxsdf_retucp->uc_link);
	setcontext(lxsdf->lxsdf_retucp);
	assert(0);

	/*NOTREACHED*/
	return (0);
}
#endif

/*
 * This signal return syscall is used by both 32-bit and 64-bit code.
 */
long
lx_rt_sigreturn(void)
{
	lx_sigdeliver_frame_t *lxsdf;
	struct lx_sigstack *lx_ssp;
	lx_ucontext_t *lx_ucp;
	ucontext_t *ucp;
	ucontext_t *sigucp;
	uintptr_t sp;

	/* Get the registers at the emulated Linux rt_sigreturn syscall */
	ucp = lx_syscall_regs();

#if defined(_ILP32)
	lx_debug("lx_rt_sigreturn: ESP %p UESP %p\n", LX_REG(ucp, ESP),
	    LX_REG(ucp, UESP));
	/*
	 * For 32-bit
	 *
	 * NOTE:  Because of the silly compatibility measures done in the
	 *	  signal trampoline code to make sure the stack holds the
	 *	   _exact same_  instruction sequence Linux does, we have to
	 *	  manually "pop" some extra instructions off the stack here
	 *	  before passing the stack address to the syscall because the
	 *	  trampoline code isn't allowed to do it due to the gdb
	 *	  compatability issues.
	 *
	 *	  No, I'm not kidding.
	 *
	 *	  The sp saved in the context is eight bytes off of where we
	 *	  need it to be (either due to trampoline or the copying of
	 *	  sp = uesp, not clear which but looks like the uesp case), so
	 *	  the need to pop the extra four byte instruction means we need
	 *	  to subtract  a net four bytes from the sp before "popping" the
	 *	  struct lx_sigstack off the stack.
	 *
	 *	  This will yield the value the stack pointer had before
	 *	  lx_sigdeliver() created the stack frame for the Linux signal
	 *	  handler.
	 */
	sp = (uintptr_t)LX_REG(ucp, REG_SP) - 4;
#else
	/*
	 * We need to make an adjustment for 64-bit code as well. Since 64-bit
	 * does not use the trampoline, it's probably for the same reason as
	 * alluded to above.
	 */
	sp = (uintptr_t)LX_REG(ucp, REG_SP) - 8;
#endif

	/*
	 * At this point, the stack pointer should point to the struct
	 * lx_sigstack that lx_build_signal_frame() constructed and
	 * placed on the stack.  We need to reference it a bit later, so
	 * save a pointer to it before incrementing our copy of the sp.
	 */
	lx_ssp = (struct lx_sigstack *)sp;
	sp += SA(sizeof (struct lx_sigstack));

#if defined(_LP64)
	/*
	 * The 64-bit lx_sigdeliver() inserts 8 bytes of padding between
	 * the lx_sigstack_t and the delivery frame to maintain ABI stack
	 * alignment.
	 */
	sp += 8;
#endif

	/*
	 * lx_sigdeliver() pushes a lx_sigdeliver_frame_t onto the stack
	 * before it creates the struct lx_oldsigstack.
	 *
	 * If we do not find it here, the stack has been corrupted and we
	 * need to kill ourselves.
	 */
	lxsdf = (lx_sigdeliver_frame_t *)sp;
	if (lxsdf->lxsdf_magic != LX_SIGRT_MAGIC) {
		lx_err_fatal("sp @ 0x%p, expected 0x%x, found 0x%x!",
		    sp, LX_SIGRT_MAGIC, lxsdf->lxsdf_magic);
	}

	sigucp = lxsdf->lxsdf_sigucp;

	/*
	 * We need to copy machine registers the Linux signal handler may have
	 * modified back to the Illumos version.
	 */
#if defined(_LP64)
	lx_ucp = &lx_ssp->uc;

	/*
	 * General register layout is completely different.
	 */
	sigucp->uc_mcontext.gregs[REG_R15] = lx_ucp->uc_sigcontext.sc_r15;
	sigucp->uc_mcontext.gregs[REG_R14] = lx_ucp->uc_sigcontext.sc_r14;
	sigucp->uc_mcontext.gregs[REG_R13] = lx_ucp->uc_sigcontext.sc_r13;
	sigucp->uc_mcontext.gregs[REG_R12] = lx_ucp->uc_sigcontext.sc_r12;
	sigucp->uc_mcontext.gregs[REG_R11] = lx_ucp->uc_sigcontext.sc_r11;
	sigucp->uc_mcontext.gregs[REG_R10] = lx_ucp->uc_sigcontext.sc_r10;
	sigucp->uc_mcontext.gregs[REG_R9] = lx_ucp->uc_sigcontext.sc_r9;
	sigucp->uc_mcontext.gregs[REG_R8] = lx_ucp->uc_sigcontext.sc_r8;
	sigucp->uc_mcontext.gregs[REG_RDI] = lx_ucp->uc_sigcontext.sc_rdi;
	sigucp->uc_mcontext.gregs[REG_RSI] = lx_ucp->uc_sigcontext.sc_rsi;
	sigucp->uc_mcontext.gregs[REG_RBP] = lx_ucp->uc_sigcontext.sc_rbp;
	sigucp->uc_mcontext.gregs[REG_RBX] = lx_ucp->uc_sigcontext.sc_rbx;
	sigucp->uc_mcontext.gregs[REG_RDX] = lx_ucp->uc_sigcontext.sc_rdx;
	sigucp->uc_mcontext.gregs[REG_RCX] = lx_ucp->uc_sigcontext.sc_rcx;
	sigucp->uc_mcontext.gregs[REG_RAX] = lx_ucp->uc_sigcontext.sc_rax;
	sigucp->uc_mcontext.gregs[REG_TRAPNO] = lx_ucp->uc_sigcontext.sc_trapno;
	sigucp->uc_mcontext.gregs[REG_ERR] = lx_ucp->uc_sigcontext.sc_err;
	sigucp->uc_mcontext.gregs[REG_RIP] = lx_ucp->uc_sigcontext.sc_rip;
	sigucp->uc_mcontext.gregs[REG_CS] = lx_ucp->uc_sigcontext.sc_cs;
	sigucp->uc_mcontext.gregs[REG_RFL] = lx_ucp->uc_sigcontext.sc_eflags;
	sigucp->uc_mcontext.gregs[REG_RSP] = lx_ucp->uc_sigcontext.sc_rsp;
	sigucp->uc_mcontext.gregs[REG_SS] = lx_ucp->uc_sigcontext.sc_pad0;
	sigucp->uc_mcontext.gregs[REG_FS] = lx_ucp->uc_sigcontext.sc_fs;
	sigucp->uc_mcontext.gregs[REG_GS] = lx_ucp->uc_sigcontext.sc_gs;

#else /* is _ILP32 */
	lx_ucp = &lx_ssp->uc;

	/*
	 * Illumos and Linux both follow the SysV i386 ABI layout for the
	 * mcontext.
	 *
	 * General registers copy across as-is, except Linux expects that
	 * changes made to uc_mcontext.gregs[ESP] will be reflected when the
	 * interrupted thread resumes execution after the signal handler. To
	 * emulate this behavior, we must modify uc_mcontext.gregs[UESP] to
	 * match uc_mcontext.gregs[ESP] as Illumos will restore the UESP value
	 * to ESP.
	 */
	lx_ucp->uc_sigcontext.sc_esp_at_signal = lx_ucp->uc_sigcontext.sc_esp;

	bcopy(&lx_ucp->uc_sigcontext, &sigucp->uc_mcontext.gregs,
	    sizeof (gregset_t));
#endif

	if (lx_ucp->uc_sigcontext.sc_fpstate != NULL) {
		ltos_fpstate(lx_ucp->uc_sigcontext.sc_fpstate,
		    &sigucp->uc_mcontext.fpregs);
	}

	/*
	 * Convert the Linux signal mask and stack back to their
	 * Illumos equivalents.
	 */
	(void) ltos_sigset(&lx_ucp->uc_sigmask, &sigucp->uc_sigmask);
	ltos_stack(&lx_ucp->uc_stack, &sigucp->uc_stack);

	/*
	 * For signal mask handling to be done properly, this call needs to
	 * return to the libc routine that originally called the signal handler
	 * rather than directly set the context back to the place the signal
	 * interrupted execution as the original Linux code would do.
	 */
	lx_debug("lx_rt_sigreturn: calling setcontext; retucp %p\n",
	    lxsdf->lxsdf_retucp);
	setcontext(lxsdf->lxsdf_retucp);
	assert(0);

	/*NOTREACHED*/
	return (0);
}


#if defined(_ILP32)
/*
 * Build signal frame for processing for "old" (legacy) Linux signals
 * This stack-builder function is only used by 32-bit code.
 */
static void
lx_build_old_signal_frame(int lx_sig, siginfo_t *sip, void *p, void *sp,
    uintptr_t *hargs)
{
	extern void lx_sigreturn_tramp();

	lx_sigset_t lx_sigset;
	ucontext_t *ucp = (ucontext_t *)p;
	struct lx_sigaction *lxsap;
	struct lx_oldsigstack *lx_ossp = sp;

	lx_debug("building old signal frame for lx sig %d at 0x%p", lx_sig, sp);

	lx_ossp->sig = lx_sig;
	lxsap = &lx_sighandlers.lx_sa[lx_sig];
	lx_debug("lxsap @ 0x%p", lxsap);

	if (lxsap && (lxsap->lxsa_flags & LX_SA_RESTORER) &&
	    lxsap->lxsa_restorer) {
		lx_ossp->retaddr = lxsap->lxsa_restorer;
		lx_debug("lxsa_restorer exists @ 0x%p", lx_ossp->retaddr);
	} else {
		lx_ossp->retaddr = lx_sigreturn_tramp;
		lx_debug("lx_ossp->retaddr set to 0x%p", lx_sigreturn_tramp);
	}

	lx_debug("osf retaddr = 0x%p", lx_ossp->retaddr);

	/* convert Illumos signal mask and stack to their Linux equivalents */
	(void) stol_sigset(&ucp->uc_sigmask, &lx_sigset);
	lx_ossp->sigc.sc_mask = lx_sigset.__bits[0];
	lx_ossp->sig_extra = lx_sigset.__bits[1];

	/*
	 * General registers copy across as-is, except Linux expects that
	 * uc_mcontext.gregs[ESP] == uc_mcontext.gregs[UESP] on receipt of a
	 * signal.
	 */
	bcopy(&ucp->uc_mcontext, &lx_ossp->sigc, sizeof (gregset_t));
	lx_ossp->sigc.sc_esp = lx_ossp->sigc.sc_esp_at_signal;

	/*
	 * cr2 contains the faulting address, and Linux only sets cr2 for a
	 * a segmentation fault.
	 */
	lx_ossp->sigc.sc_cr2 = (((lx_sig == LX_SIGSEGV) && (sip)) ?
	    (uintptr_t)sip->si_addr : 0);

	/* convert FP regs if present */
	if (ucp->uc_flags & UC_FPU) {
		stol_fpstate(&ucp->uc_mcontext.fpregs, &lx_ossp->fpstate);
		lx_ossp->sigc.sc_fpstate = &lx_ossp->fpstate;
	} else {
		lx_ossp->sigc.sc_fpstate = NULL;
	}

	/*
	 * Believe it or not, gdb wants to SEE the trampoline code on the
	 * bottom of the stack to determine whether the stack frame belongs to
	 * a signal handler, even though this code is no longer actually
	 * called.
	 *
	 * You can't make this stuff up.
	 */
	bcopy((void *)lx_sigreturn_tramp, lx_ossp->trampoline,
	    sizeof (lx_ossp->trampoline));

	LX_SIGDELIVER(lx_sig, lxsap, NULL, NULL);
}
#endif

/*
 * Build stack frame (32-bit) or stack local data (64-bit) for processing for
 * modern Linux signals. This is the only stack-builder function for 64-bit
 * code (32-bit code also calls this when using "modern" signals).
 */
static void
lx_build_signal_frame(int lx_sig, siginfo_t *sip, void *p, void *sp,
    uintptr_t *hargs)
{
	extern void lx_rt_sigreturn_tramp();

	lx_ucontext_t *lx_ucp;
	ucontext_t *ucp = (ucontext_t *)p;
	struct lx_sigstack *lx_ssp = sp;
	struct lx_sigaction *lxsap;

	lx_debug("building signal frame for lx sig %d at 0x%p", lx_sig, sp);

	lx_ucp = &lx_ssp->uc;
#if defined(_ILP32)
	/*
	 * Arguments are passed to the 32-bit signal handler on the stack.
	 */
	lx_ssp->ucp = lx_ucp;
	lx_ssp->sip = sip != NULL ? &lx_ssp->si : NULL;
	lx_ssp->sig = lx_sig;
#else
	/*
	 * Arguments to the 64-bit signal handler are passed in registers:
	 *   hdlr(int sig, siginfo_t *sip, void *ucp);
	 */
	hargs[0] = lx_sig;
	hargs[1] = sip != NULL ? (uintptr_t)&lx_ssp->si : NULL;
	hargs[2] = (uintptr_t)lx_ucp;
#endif

	lxsap = &lx_sighandlers.lx_sa[lx_sig];
	lx_debug("lxsap @ 0x%p", lxsap);

	if (lxsap && (lxsap->lxsa_flags & LX_SA_RESTORER) &&
	    lxsap->lxsa_restorer) {
		/*
		 * lxsa_restorer is explicitly set by sigaction in 32-bit code
		 * but it can also be implicitly set for both 32 and 64 bit
		 * code via lx_sigaction_common when we bcopy the user-supplied
		 * lx_sigaction element into the proper slot in the sighandler
		 * array.
		 */
		lx_ssp->retaddr = lxsap->lxsa_restorer;
		lx_debug("lxsa_restorer exists @ 0x%p", lx_ssp->retaddr);
	} else {
		lx_ssp->retaddr = lx_rt_sigreturn_tramp;
		lx_debug("lx_ssp->retaddr set to 0x%p", lx_rt_sigreturn_tramp);
	}

	/* Linux has these fields but always clears them to 0 */
	lx_ucp->uc_flags = 0;
	lx_ucp->uc_link = NULL;

	/* convert Illumos signal mask and stack to their Linux equivalents */
	(void) stol_sigset(&ucp->uc_sigmask, &lx_ucp->uc_sigmask);
	stol_stack(&ucp->uc_stack, &lx_ucp->uc_stack);

#if defined(_LP64)
	/*
	 * General register layout is completely different.
	 */
	lx_ucp->uc_sigcontext.sc_r8 = ucp->uc_mcontext.gregs[REG_R8];
	lx_ucp->uc_sigcontext.sc_r9 = ucp->uc_mcontext.gregs[REG_R9];
	lx_ucp->uc_sigcontext.sc_r10 = ucp->uc_mcontext.gregs[REG_R10];
	lx_ucp->uc_sigcontext.sc_r11 = ucp->uc_mcontext.gregs[REG_R11];
	lx_ucp->uc_sigcontext.sc_r12 = ucp->uc_mcontext.gregs[REG_R12];
	lx_ucp->uc_sigcontext.sc_r13 = ucp->uc_mcontext.gregs[REG_R13];
	lx_ucp->uc_sigcontext.sc_r14 = ucp->uc_mcontext.gregs[REG_R14];
	lx_ucp->uc_sigcontext.sc_r15 = ucp->uc_mcontext.gregs[REG_R15];
	lx_ucp->uc_sigcontext.sc_rdi = ucp->uc_mcontext.gregs[REG_RDI];
	lx_ucp->uc_sigcontext.sc_rsi = ucp->uc_mcontext.gregs[REG_RSI];
	lx_ucp->uc_sigcontext.sc_rbp = ucp->uc_mcontext.gregs[REG_RBP];
	lx_ucp->uc_sigcontext.sc_rbx = ucp->uc_mcontext.gregs[REG_RBX];
	lx_ucp->uc_sigcontext.sc_rdx = ucp->uc_mcontext.gregs[REG_RDX];
	lx_ucp->uc_sigcontext.sc_rax = ucp->uc_mcontext.gregs[REG_RAX];
	lx_ucp->uc_sigcontext.sc_rcx = ucp->uc_mcontext.gregs[REG_RCX];
	lx_ucp->uc_sigcontext.sc_rsp = ucp->uc_mcontext.gregs[REG_RSP];
	lx_ucp->uc_sigcontext.sc_rip = ucp->uc_mcontext.gregs[REG_RIP];
	lx_ucp->uc_sigcontext.sc_eflags = ucp->uc_mcontext.gregs[REG_RFL];
	lx_ucp->uc_sigcontext.sc_cs = ucp->uc_mcontext.gregs[REG_CS];
	lx_ucp->uc_sigcontext.sc_gs = ucp->uc_mcontext.gregs[REG_GS];
	lx_ucp->uc_sigcontext.sc_fs = ucp->uc_mcontext.gregs[REG_FS];
	lx_ucp->uc_sigcontext.sc_pad0 = ucp->uc_mcontext.gregs[REG_SS];
	lx_ucp->uc_sigcontext.sc_err = ucp->uc_mcontext.gregs[REG_ERR];
	lx_ucp->uc_sigcontext.sc_trapno = ucp->uc_mcontext.gregs[REG_TRAPNO];

#else /* is _ILP32 */
	/*
	 * General registers copy across as-is, except Linux expects that
	 * uc_mcontext.gregs[ESP] == uc_mcontext.gregs[UESP] on receipt of a
	 * signal.
	 */
	bcopy(&ucp->uc_mcontext, &lx_ucp->uc_sigcontext, sizeof (gregset_t));
	lx_ucp->uc_sigcontext.sc_esp = lx_ucp->uc_sigcontext.sc_esp_at_signal;
#endif

	/*
	 * cr2 contains the faulting address, which Linux only sets for a
	 * a segmentation fault.
	 */
	lx_ucp->uc_sigcontext.sc_cr2 = ((lx_sig == LX_SIGSEGV) && (sip)) ?
	    (uintptr_t)sip->si_addr : 0;

	/*
	 * This should only return an error if the signum is invalid but that
	 * also gets converted into a LX_SIGKILL by this function.
	 */
	if (sip != NULL)
		(void) stol_siginfo(sip, &lx_ssp->si);
	else
		bzero(&lx_ssp->si, sizeof (lx_siginfo_t));

	/* convert FP regs if present */
	if (ucp->uc_flags & UC_FPU) {
		/*
		 * Copy FP regs to the appropriate place in the the lx_sigstack
		 * structure.
		 */
		stol_fpstate(&ucp->uc_mcontext.fpregs, &lx_ssp->fpstate);
		lx_ucp->uc_sigcontext.sc_fpstate = &lx_ssp->fpstate;
	} else {
		lx_ucp->uc_sigcontext.sc_fpstate = NULL;
	}

#if defined(_ILP32)
	/*
	 * Believe it or not, gdb wants to SEE the sigreturn code on the
	 * top of the stack to determine whether the stack frame belongs to
	 * a signal handler, even though this code is not actually called.
	 *
	 * You can't make this stuff up.
	 */
	bcopy((void *)lx_rt_sigreturn_tramp, lx_ssp->trampoline,
	    sizeof (lx_ssp->trampoline));
#endif

	LX_SIGDELIVER(lx_sig, lxsap, lx_ssp, lx_ucp);
}

/*
 * This is the second level interposition handler for Linux signals.
 */
static void
lx_call_user_handler(int sig, siginfo_t *sip, void *p)
{
	void (*user_handler)();
	void (*stk_builder)();
	struct lx_sigaction *lxsap;
	ucontext_t *ucp = (ucontext_t *)p;
	size_t stksize;
	int lx_sig;

	/*
	 * If Illumos signal has no Linux equivalent, effectively ignore it.
	 */
	if ((lx_sig = stol_signo[sig]) == -1) {
		lx_unsupported("caught Illumos signal %d, no Linux equivalent",
		    sig);
		return;
	}

	lx_debug("interpose caught Illumos signal %d, translating to Linux "
	    "signal %d", sig, lx_sig);

	lxsap = &lx_sighandlers.lx_sa[lx_sig];
	lx_debug("lxsap @ 0x%p", lxsap);

	/*
	 * We bounce into the kernel for the Linux ptrace(2)
	 * "signal-delivery-stop".  If we are being traced, the tracer may
	 * modify the topmost BRAND-mode ucontext before we are restarted.
	 */
	(void) syscall(SYS_brand, B_PTRACE_STOP_FOR_SIGNAL, lx_find_brand_uc(),
	    lx_sig);

	if ((sig == SIGPWR) && (lxsap->lxsa_handler == SIG_DFL)) {
		/*
		 * Linux SIG_DFL for SIGPWR is to terminate. The lx wait
		 * emulation will translate SIGPWR to LX_SIGPWR.
		 */
		(void) syscall(SYS_brand, B_EXIT_AS_SIG, SIGPWR);
		/* This should never return */
		assert(0);
	}

	if (lxsap->lxsa_handler == SIG_DFL || lxsap->lxsa_handler == SIG_IGN)
		lx_err_fatal("lxsa_handler set to %s?  How?!?!?",
		    (lxsap->lxsa_handler == SIG_DFL) ? "SIG_DFL" : "SIG_IGN");

#if defined(_LP64)
	stksize = sizeof (struct lx_sigstack);
	stk_builder = lx_build_signal_frame;
#else
	if (lxsap->lxsa_flags & LX_SA_SIGINFO) {
		stksize = sizeof (struct lx_sigstack);
		stk_builder = lx_build_signal_frame;
	} else  {
		stksize = sizeof (struct lx_oldsigstack);
		stk_builder = lx_build_old_signal_frame;
	}
#endif

	user_handler = lxsap->lxsa_handler;

	lx_debug("delivering %d (lx %d) to handler at 0x%p", sig, lx_sig,
	    lxsap->lxsa_handler);

	if (lxsap->lxsa_flags & LX_SA_RESETHAND)
		lxsap->lxsa_handler = SIG_DFL;

	/*
	 * Construct the signal handling stack frame and deliver the signal.
	 * This routine will not return until the Linux signal handler has
	 * completed execution.
	 */
	lx_sigdeliver(lx_sig, sip, ucp, stksize, stk_builder, user_handler,
	    lxsap);

	/*
	 * We need to handle restarting interrupted system calls if requested
	 * by the program:
	 */
	if (lxsap->lxsa_flags & LX_SA_RESTART) {
		unsigned int flags = (uintptr_t)ucp->uc_brand_data[0];
		long ret = (long)LX_REG(ucp, REG_R0);

		if (flags & LX_UC_RESTART_SYSCALL && ret == -lx_errno(EINTR)) {
			lx_debug("restarting interrupted system call %d",
			    (int)(uintptr_t)ucp->uc_brand_data[0]);
			/*
			 * Both the "int80" and "syscall" instructions are
			 * two bytes long.  If we wind back by two bytes,
			 * the system call will fire again when we restore
			 * the context.
			 */
			LX_REG(ucp, REG_PC) -= 2;
			LX_REG(ucp, REG_R0) =
			    (int)(uintptr_t)ucp->uc_brand_data[2];
		}
	}
}

/*
 * XXX
 */
void
lx_sigdeliver(int lx_sig, siginfo_t *sip, ucontext_t *ucp, size_t stacksz,
    void (*stack_builder)(), void (*user_handler)(),
    struct lx_sigaction *lxsap)
{
	ucontext_t uc;
	lx_tsd_t *lxtsd = lx_get_tsd();
	int totsz = 0;
	uintptr_t flags;
	uintptr_t hargs[3];
	/*
	 * These variables must be "volatile", as they are modified after the
	 * getcontext() stores the register state:
	 */
	volatile boolean_t signal_delivered = B_FALSE;
	volatile uintptr_t lxfp;
	volatile uintptr_t old_tsd_sp;
	volatile int newstack;

	extern void _sigoff(void);
	extern void _sigon(void);

	/*
	 * This function involves modifying the Linux process stack for this
	 * thread.  To do so without corruption requires us to exclude other
	 * signal handlers (or emulated system calls called from within those
	 * handlers) from running while we reserve space on that stack.  We
	 * defer the execution of further instances of lx_call_user_handler()
	 * until we have completed this operation.
	 */
	_sigoff();

	/*
	 * Clear register arguments vector.
	 */
	bzero(hargs, sizeof (hargs));

	/*
	 * We save a context here so that we can be returned later to complete
	 * handling the signal.
	 */
	lx_debug("lx_sigdeliver: STORING RETURN CONTEXT @ %p\n", &uc);
	assert(getcontext(&uc) == 0);
	lx_debug("lx_sigdeliver: RETURN CONTEXT %p LINK %p FLAGS %lx\n",
	    &uc, uc.uc_link, uc.uc_flags);
	if (signal_delivered) {
		/*
		 * If the "signal_delivered" flag is set, we are returned here
		 * via setcontext() as called by the emulated Linux signal
		 * return system call.
		 */
		lx_debug("lx_sigdeliver: WE ARE BACK, VIA UC @ %p!\n", &uc);
		goto after_signal_handler;
	}
	signal_delivered = B_TRUE;

	/*
	 * Preserve the current tsd value of the Linux process stack pointer,
	 * even if it is zero.  We will restore it when we are returned here
	 * via setcontext() after the Linux process has completed execution of
	 * its signal handler.
	 */
	old_tsd_sp = lxtsd->lxtsd_lx_sp;

	/*
	 * Figure out whether we will be handling this signal on an alternate
	 * stack specified by the user.
	 */
	newstack = (lxsap->lxsa_flags & LX_SA_ONSTACK) &&
	    !(lxtsd->lxtsd_sigaltstack.ss_flags & (LX_SS_ONSTACK |
	    LX_SS_DISABLE));

	/*
	 * Find the first unused region of the Linux process stack, where
	 * we will assemble our signal delivery frame.
	 */
	flags = (uintptr_t)ucp->uc_brand_data[0];
	if (newstack) {
		/*
		 * We are moving to the user-provided alternate signal
		 * stack.
		 */
		lxfp = SA((uintptr_t)lxtsd->lxtsd_sigaltstack.ss_sp) +
		    SA(lxtsd->lxtsd_sigaltstack.ss_size) - STACK_ALIGN;
		lx_debug("lx_sigdeliver: moving to ALTSTACK sp %p\n", lxfp);
		LX_SIGNAL_ALTSTACK_ENABLE(lxfp);
	} else if (flags & LX_UC_STACK_BRAND) {
		/*
		 * We interrupted the Linux process to take this signal.  The
		 * stack pointer is the one saved in this context.
		 */
		lxfp = LX_REG(ucp, REG_SP);
	} else {
		/*
		 * We interrupted a native (emulation) routine, so we must get
		 * the current stack pointer from either the tsd (if one is
		 * stored there) or via the context chain.
		 *
		 */
		lxfp = lx_find_brand_sp();
		if (lxtsd->lxtsd_lx_sp != 0) {
			/*
			 * We must also make room for the possibility of nested
			 * signal delivery -- we may be pre-empting the
			 * in-progress handling of another signal.
			 *
			 * Note that if we were already on the alternate stack,
			 * any emulated Linux system calls would be betwixt
			 * that original signal frame and this new one on the
			 * one contiguous stack, so this logic holds either
			 * way:
			 */
			lxfp = MIN(lxtsd->lxtsd_lx_sp, lxfp);
		}
	}

	/*
	 * Account for a reserved stack region (for amd64, this is 128 bytes),
	 * and align the stack:
	 */
	lxfp -= STACK_RESERVE;
	lxfp &= ~(STACK_ALIGN - 1);

	/*
	 * Allocate space on the Linux process stack for our delivery frame,
	 * including:
	 *
	 *   ----------------------------------------------------- old %sp
	 *   | lx_sigdeliver_frame_t
	 *   | (ucontext_t pointers and stack magic)
	 *   |----------------------------------------------------
	 *   | (amd64-only 8-byte alignment gap)
	 *   |----------------------------------------------------
	 *   V frame of size "stacksz" from the stack builder
	 *   ----------------------------------------------------- new %sp
	 */
#if defined(_LP64)
	/*
	 * The AMD64 ABI requires us to align the stack such that when the
	 * called function pushes the base pointer, the stack is 16 byte
	 * aligned.  The stack must, therefore, be 8- but _not_ 16-byte
	 * aligned.
	 */
#if (STACK_ALIGN != 16) || (STACK_ENTRY_ALIGN != 8)
#error "lx_sigdeliver() did not find expected stack alignment"
#endif
	totsz = SA(sizeof (lx_sigdeliver_frame_t)) + SA(stacksz) + 8;
	assert((totsz & (STACK_ENTRY_ALIGN - 1)) == 0);
	assert((totsz & (STACK_ALIGN - 1)) == 8);
#else
	totsz = SA(sizeof (lx_sigdeliver_frame_t)) + SA(stacksz);
	assert((totsz & (STACK_ALIGN - 1)) == 0);
#endif

	/*
	 * Copy our return frame into place:
	 */
	lxfp -= SA(sizeof (lx_sigdeliver_frame_t));
	lx_debug("lx_sigdeliver: lx_sigdeliver_frame_t @ %p\n", lxfp);
	{
		lx_sigdeliver_frame_t frm;

		frm.lxsdf_magic = LX_SIGRT_MAGIC;
		frm.lxsdf_retucp = &uc;
		frm.lxsdf_sigucp = ucp;

		lx_debug("lx_sigdeliver: retucp %p sigucp %p\n",
		    frm.lxsdf_retucp, frm.lxsdf_sigucp);

		if (uucopy(&frm, (void *)lxfp, sizeof (frm)) != 0) {
			/*
			 * XXX should induce SIGSEGV here, probably.
			 */
			lx_err_fatal("could not write to Linux stack");
		}

		LX_SIGNAL_DELIVERY_FRAME_CREATE((void *)lxfp);
	}

	/*
	 * Build the Linux signal handling frame:
	 */
#if defined(_LP64)
	lxfp -= SA(stacksz) + 8;
#else
	lxfp -= SA(stacksz);
#endif
	lx_debug("lx_sigdeliver: Linux sig frame @ %p\n", lxfp);
	stack_builder(lx_sig, sip, ucp, lxfp, hargs);

	/*
	 * Record our reservation so that any nested signal handlers
	 * can see it.
	 */
	lx_debug("lx_sigdeliver: Linux tsd sp %p -> %p\n", lxtsd->lxtsd_lx_sp,
	    lxfp);
	lxtsd->lxtsd_lx_sp = lxfp;

	if (newstack) {
		lxtsd->lxtsd_sigaltstack.ss_flags |= LX_SS_ONSTACK;
	}

	/*
	 * Re-enable signal delivery.  If a signal was queued while we were
	 * in the critical section, it will be delivered immediately.
	 */
	_sigon();

	/*
	 * Pass control to the Linux signal handler:
	 */
	lx_debug("lx_sigdeliver: JUMPING TO LINUX (sig %d sp %p eip %p)\n",
	    lx_sig, lxfp, user_handler);
	{
		ucontext_t jump_uc;

		bcopy(lx_find_brand_uc(), &jump_uc, sizeof (jump_uc));

		/*
		 * We want to load the general registers from this context, and
		 * switch to the BRAND stack.  We do _not_ want to restore the
		 * uc_link value from this synthetic context, as that would
		 * break the signal handling context chain.
		 */
		jump_uc.uc_flags = UC_CPU;
		jump_uc.uc_brand_data[0] = (void *)(LX_UC_STACK_BRAND |
		    LX_UC_IGNORE_LINK);

		jump_uc.uc_mcontext.gregs[REG_FP] = 0;
		jump_uc.uc_mcontext.gregs[REG_SP] = lxfp;
		jump_uc.uc_mcontext.gregs[REG_PC] = (uintptr_t)user_handler;

#if defined(_LP64)
		/*
		 * Pass signal handler arguments by registers on AMD64.
		 */
		jump_uc.uc_mcontext.gregs[REG_RDI] = hargs[0];
		jump_uc.uc_mcontext.gregs[REG_RSI] = hargs[1];
		jump_uc.uc_mcontext.gregs[REG_RDX] = hargs[2];
#endif

		if (syscall(SYS_brand, B_JUMP_TO_LINUX, &jump_uc) == -1) {
			lx_err_fatal("B_JUMP_TO_LINUX failed: %s",
			    strerror(errno));
		}
	}


	assert(0);

after_signal_handler:
	/*
	 * Ensure all nested signal handlers have completed correctly
	 * and then remove our stack reservation.
	 */
	_sigoff();
	LX_SIGNAL_POST_HANDLER(lxfp, old_tsd_sp);
	assert(lxtsd->lxtsd_lx_sp == lxfp);
	lx_debug("lx_sigdeliver: after; Linux tsd sp %p -> %p\n", lxfp,
	    old_tsd_sp);
	lxtsd->lxtsd_lx_sp = old_tsd_sp;
	if (newstack) {
		LX_SIGNAL_ALTSTACK_DISABLE();
		lx_debug("lx_sigdeliver: disabling ALTSTACK sp %p\n", lxfp);
		lxtsd->lxtsd_sigaltstack.ss_flags &= ~LX_SS_ONSTACK;
	}
	_sigon();

	/*
	 * Here we return to libc so that it may clean up and restore the
	 * context originally interrupted by this signal.
	 */
}

/*
 * Common routine to modify sigaction characteristics of a thread.
 *
 * We shouldn't need any special locking code here as we actually use our copy
 * of libc's sigaction() to do all the real work, so its thread locking should
 * take care of any issues for us.
 */
static int
lx_sigaction_common(int lx_sig, struct lx_sigaction *lxsp,
    struct lx_sigaction *olxsp)
{
	struct lx_sigaction *lxsap;
	struct sigaction sa;

	if (lx_sig <= 0 || lx_sig > LX_NSIG)
		return (-EINVAL);

	lxsap = &lx_sighandlers.lx_sa[lx_sig];
	lx_debug("&lx_sighandlers.lx_sa[%d] = 0x%p", lx_sig, lxsap);

	if ((olxsp != NULL) &&
	    ((uucopy(lxsap, olxsp, sizeof (struct lx_sigaction))) != 0))
		return (-errno);

	if (lxsp != NULL) {
		int err, sig;
		struct lx_sigaction lxsa;
		sigset_t new_set, oset;

		if (uucopy(lxsp, &lxsa, sizeof (struct lx_sigaction)) != 0)
			return (-errno);

		if ((sig = ltos_signo[lx_sig]) != -1) {
			if (sig == SIGABRT)
				return (0);
			/*
			 * Block this signal while messing with its dispostion
			 */
			(void) sigemptyset(&new_set);
			(void) sigaddset(&new_set, sig);

			if (sigprocmask(SIG_BLOCK, &new_set, &oset) < 0) {
				err = errno;
				lx_debug("unable to block signal %d: %s", sig,
				    strerror(err));
				return (-err);
			}

			/*
			 * We don't really need the old signal disposition at
			 * this point, but this weeds out signals that would
			 * cause sigaction() to return an error before we change
			 * anything other than the current signal mask.
			 */
			if (sigaction(sig, NULL, &sa) < 0) {
				err = errno;
				lx_debug("sigaction() to get old "
				    "disposition for signal %d failed: "
				    "%s", sig, strerror(err));
				(void) sigprocmask(SIG_SETMASK, &oset, NULL);
				return (-err);
			}

			if ((lxsa.lxsa_handler != SIG_DFL) &&
			    (lxsa.lxsa_handler != SIG_IGN)) {
				sa.sa_handler = lx_call_user_handler;

				/*
				 * The interposition signal handler needs the
				 * information provided via the SA_SIGINFO flag.
				 */
				sa.sa_flags = SA_SIGINFO;

				/*
				 * When translating from Linux to illumos
				 * sigaction(2) flags, we explicitly do not
				 * pass SA_ONSTACK to the kernel.  The
				 * alternate stack for Linux signal handling is
				 * handled entirely by the emulation code.
				 */
				if (lxsa.lxsa_flags & LX_SA_NOCLDSTOP)
					sa.sa_flags |= SA_NOCLDSTOP;
				if (lxsa.lxsa_flags & LX_SA_NOCLDWAIT)
					sa.sa_flags |= SA_NOCLDWAIT;
				if (lxsa.lxsa_flags & LX_SA_RESTART)
					sa.sa_flags |= SA_RESTART;
				if (lxsa.lxsa_flags & LX_SA_NODEFER)
					sa.sa_flags |= SA_NODEFER;

				/*
				 * Can't use RESETHAND with SIGPWR due to
				 * different default actions between Linux
				 * and Illumos.
				 */
				if ((sig != SIGPWR) &&
				    (lxsa.lxsa_flags & LX_SA_RESETHAND))
					sa.sa_flags |= SA_RESETHAND;

				if (ltos_sigset(&lxsa.lxsa_mask,
				    &sa.sa_mask) != 0) {
					err = errno;
					(void) sigprocmask(SIG_SETMASK, &oset,
					    NULL);
					return (-err);
				}

				lx_debug("interposing handler @ 0x%p for "
				    "signal %d (lx %d), flags 0x%x",
				    lxsa.lxsa_handler, sig, lx_sig,
				    lxsa.lxsa_flags);

				if (sigaction(sig, &sa, NULL) < 0) {
					err = errno;
					lx_debug("sigaction() to set new "
					    "disposition for signal %d failed: "
					    "%s", sig, strerror(err));
					(void) sigprocmask(SIG_SETMASK, &oset,
					    NULL);
					return (-err);
				}
			} else if ((sig != SIGPWR) ||
			    ((sig == SIGPWR) &&
			    (lxsa.lxsa_handler == SIG_IGN))) {
				/*
				 * There's no need to interpose for SIG_DFL or
				 * SIG_IGN so just call our copy of libc's
				 * sigaction(), but don't allow SIG_DFL for
				 * SIGPWR due to differing default actions
				 * between Linux and Illumos.
				 *
				 * Get the previous disposition first so things
				 * like sa_mask and sa_flags are preserved over
				 * a transition to SIG_DFL or SIG_IGN, which is
				 * what Linux expects.
				 */

				sa.sa_handler = lxsa.lxsa_handler;

				if (sigaction(sig, &sa, NULL) < 0) {
					err = errno;
					lx_debug("sigaction(%d, %s) failed: %s",
					    sig, ((sa.sa_handler == SIG_DFL) ?
					    "SIG_DFL" : "SIG_IGN"),
					    strerror(err));
					(void) sigprocmask(SIG_SETMASK, &oset,
					    NULL);
					return (-err);
				}
			}
		} else {
			lx_debug("Linux signal with no kill support "
			    "specified: %d", lx_sig);
		}

		/*
		 * Save the new disposition for the signal in the global
		 * lx_sighandlers structure.
		 */
		bcopy(&lxsa, lxsap, sizeof (struct lx_sigaction));

		/*
		 * Reset the signal mask to what we came in with if
		 * we were modifying a kill-supported signal.
		 */
		if (sig != -1)
			(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	}

	return (0);
}

#if defined(_ILP32)
/*
 * sigaction is only used in 32-bit code.
 */
long
lx_sigaction(uintptr_t lx_sig, uintptr_t actp, uintptr_t oactp)
{
	int val;
	struct lx_sigaction sa, osa;
	struct lx_sigaction *sap, *osap;
	struct lx_osigaction *osp;

	sap = (actp ? &sa : NULL);
	osap = (oactp ? &osa : NULL);

	/*
	 * If we have a source pointer, convert source lxsa_mask from
	 * lx_osigset_t to lx_sigset_t format.
	 */
	if (sap) {
		osp = (struct lx_osigaction *)actp;
		sap->lxsa_handler = osp->lxsa_handler;

		bzero(&sap->lxsa_mask, sizeof (lx_sigset_t));

		for (val = 1; val <= OSIGSET_NBITS; val++)
			if (osp->lxsa_mask & OSIGSET_BITSET(val))
				(void) lx_sigaddset(&sap->lxsa_mask, val);

		sap->lxsa_flags = osp->lxsa_flags;
		sap->lxsa_restorer = osp->lxsa_restorer;
	}

	if ((val = lx_sigaction_common(lx_sig, sap, osap)))
		return (val);

	/*
	 * If we have a save pointer, convert the old lxsa_mask from
	 * lx_sigset_t to lx_osigset_t format.
	 */
	if (osap) {
		osp = (struct lx_osigaction *)oactp;

		osp->lxsa_handler = osap->lxsa_handler;

		bzero(&osp->lxsa_mask, sizeof (osp->lxsa_mask));
		for (val = 1; val <= OSIGSET_NBITS; val++)
			if (lx_sigismember(&osap->lxsa_mask, val))
				osp->lxsa_mask |= OSIGSET_BITSET(val);

		osp->lxsa_flags = osap->lxsa_flags;
		osp->lxsa_restorer = osap->lxsa_restorer;
	}

	return (0);
}
#endif

long
lx_rt_sigaction(uintptr_t lx_sig, uintptr_t actp, uintptr_t oactp,
    uintptr_t setsize)
{
	/*
	 * The "new" rt_sigaction call checks the setsize
	 * parameter.
	 */
	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	return (lx_sigaction_common(lx_sig, (struct lx_sigaction *)actp,
	    (struct lx_sigaction *)oactp));
}

#if defined(_ILP32)
/*
 * Convert signal syscall to a call to the lx_sigaction() syscall
 * Only used in 32-bit code.
 */
long
lx_signal(uintptr_t lx_sig, uintptr_t handler)
{
	struct sigaction act;
	struct sigaction oact;
	int rc;

	/*
	 * Use sigaction to mimic SYSV signal() behavior; glibc will
	 * actually call sigaction(2) itself, so we're really reaching
	 * back for signal(2) semantics here.
	 */
	bzero(&act, sizeof (act));
	act.sa_handler = (void (*)())handler;
	act.sa_flags = SA_RESETHAND | SA_NODEFER;

	rc = lx_sigaction(lx_sig, (uintptr_t)&act, (uintptr_t)&oact);
	return ((rc == 0) ? ((ssize_t)oact.sa_handler) : rc);
}
#endif

int
lx_siginit(void)
{
	extern void set_setcontext_enforcement(int);
	extern void set_escaped_context_cleanup(int);

	struct sigaction sa;
	sigset_t new_set, oset;
	int lx_sig, sig;

	/*
	 * Block all signals possible while setting up the signal imposition
	 * mechanism.
	 */
	(void) sigfillset(&new_set);

	if (sigprocmask(SIG_BLOCK, &new_set, &oset) < 0)
		lx_err_fatal("unable to block signals while setting up "
		    "imposition mechanism: %s", strerror(errno));

	/*
	 * Ignore any signals that have no Linux analog so that those
	 * signals cannot be sent to Linux processes from the global zone
	 */
	for (sig = 1; sig < NSIG; sig++)
		if (stol_signo[sig] < 0)
			(void) sigignore(sig);

	/*
	 * Mark any signals that are ignored as ignored in our interposition
	 * handler array
	 */
	for (lx_sig = 1; lx_sig <= LX_NSIG; lx_sig++) {
		if (((sig = ltos_signo[lx_sig]) != -1) &&
		    (sigaction(sig, NULL, &sa) < 0))
			lx_err_fatal("unable to determine previous disposition "
			    "for signal %d: %s", sig, strerror(errno));

		if (sa.sa_handler == SIG_IGN) {
			lx_debug("marking signal %d (lx %d) as SIG_IGN",
			    sig, lx_sig);
			lx_sighandlers.lx_sa[lx_sig].lxsa_handler = SIG_IGN;
		}
	}

	/*
	 * Have our interposition handler handle SIGPWR to start with,
	 * as it has a default action of terminating the process in Linux
	 * but its default is to be ignored in Illumos.
	 */
	(void) sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = lx_call_user_handler;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGPWR, &sa, NULL) < 0)
		lx_err_fatal("sigaction(SIGPWR) failed: %s", strerror(errno));

	/*
	 * Illumos' libc forces certain register values in the ucontext_t
	 * used to restore a post-signal user context to be those Illumos
	 * expects; however that is not what we want to happen if the signal
	 * was taken while branded code was executing, so we must disable
	 * that behavior.
	 */
	set_setcontext_enforcement(0);

	/*
	 * XXX
	 */
	set_escaped_context_cleanup(0);

	/*
	 * Reset the signal mask to what we came in with
	 */
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);

	lx_debug("interposition handler setup for SIGPWR");
	return (0);
}

/*
 * This code stongly resemebles lx_poll(), but is here to be able to take
 * advantage of the Linux signal helper routines.
 */
long
lx_ppoll(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5)
{
	struct pollfd   *lfds, *sfds;
	nfds_t		nfds = (nfds_t)p2;
	timespec_t	ts, *tsp = NULL;
	int		fds_size, i, rval, revents;
	lx_sigset_t	lxsig, *lxsigp = NULL;
	sigset_t	sigset, *sp = NULL;
	rctlblk_t	*rblk;

	lx_debug("\tppoll(0x%p, %d, 0x%p, 0x%p, %d)", p1, p2, p3, p4, p5);

	if (p3 != NULL) {
		if (uucopy((void *)p3, &ts, sizeof (ts)) != 0)
			return (-errno);

		tsp = &ts;
	}

	if (p4 != NULL) {
		if (uucopy((void *)p4, &lxsig, sizeof (lxsig)) != 0)
			return (-errno);

		lxsigp = &lxsig;
		if ((size_t)p5 != sizeof (lx_sigset_t))
			return (-EINVAL);

		if (lxsigp) {
			if ((rval = ltos_sigset(lxsigp, &sigset)) != 0)
				return (rval);

			sp = &sigset;
		}
	}

	/*
	 * Deal with the NULL fds[] case.
	 */
	if (nfds == 0 || p1 == NULL) {
		if ((rval = ppoll(NULL, 0, tsp, sp)) < 0)
			return (-errno);

		return (rval);
	}

	if (maxfd == 0) {
		if ((rblk = (rctlblk_t *)SAFE_ALLOCA(rctlblk_size())) == NULL)
			return (-ENOMEM);

		if (getrctl("process.max-file-descriptor", NULL, rblk,
		    RCTL_FIRST) == -1)
			return (-EINVAL);

		maxfd = rctlblk_get_value(rblk);
	}

	if (nfds > maxfd)
		return (-EINVAL);

	/*
	 * Note: we are assuming that the Linux and Illumos pollfd
	 * structures are identical.  Copy in the Linux poll structure.
	 */
	fds_size = sizeof (struct pollfd) * nfds;
	lfds = (struct pollfd *)SAFE_ALLOCA(fds_size);
	if (lfds == NULL)
		return (-ENOMEM);
	if (uucopy((void *)p1, lfds, fds_size) != 0)
		return (-errno);

	/*
	 * The poll system call modifies the poll structures passed in
	 * so we'll need to make an extra copy of them.
	 */
	sfds = (struct pollfd *)SAFE_ALLOCA(fds_size);
	if (sfds == NULL)
		return (-ENOMEM);

	/* Convert the Linux events bitmask into the Illumos equivalent. */
	for (i = 0; i < nfds; i++) {
		/*
		 * If the caller is polling for an unsupported event, we
		 * have to bail out.
		 */
		if (lfds[i].events & ~LX_POLL_SUPPORTED_EVENTS) {
			lx_unsupported("unsupported poll events requested: "
			    "events=0x%x", lfds[i].events);
			return (-ENOTSUP);
		}

		sfds[i].fd = lfds[i].fd;
		sfds[i].events = lfds[i].events & LX_POLL_COMMON_EVENTS;
		if (lfds[i].events & LX_POLLWRNORM)
			sfds[i].events |= POLLWRNORM;
		if (lfds[i].events & LX_POLLWRBAND)
			sfds[i].events |= POLLWRBAND;
		if (lfds[i].events & LX_POLLRDHUP)
			sfds[i].events |= POLLRDHUP;
		sfds[i].revents = 0;
	}

	if ((rval = ppoll(sfds, nfds, tsp, sp) < 0))
		return (-errno);

	/* Convert the Illumos revents bitmask into the Linux equivalent */
	for (i = 0; i < nfds; i++) {
		revents = sfds[i].revents & LX_POLL_COMMON_EVENTS;
		if (sfds[i].revents & POLLWRBAND)
			revents |= LX_POLLWRBAND;
		if (sfds[i].revents & POLLRDHUP)
			revents |= LX_POLLRDHUP;

		/*
		 * Be careful because on Illumos POLLOUT and POLLWRNORM
		 * are defined to the same values but on Linux they
		 * are not.
		 */
		if (sfds[i].revents & POLLOUT) {
			if ((lfds[i].events & LX_POLLOUT) == 0)
				revents &= ~LX_POLLOUT;
			if (lfds[i].events & LX_POLLWRNORM)
				revents |= LX_POLLWRNORM;
		}

		lfds[i].revents = revents;
	}

	/* Copy out the results */
	if (uucopy(lfds, (void *)p1, fds_size) != 0)
		return (-errno);

	return (rval);
}

/*
 * This code stongly resemebles lx_select(), but is here to be able to take
 * advantage of the Linux signal helper routines.
 */
long
lx_pselect6(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
	uintptr_t p5, uintptr_t p6)
{
	int nfds = (int)p1;
	fd_set *rfdsp = NULL;
	fd_set *wfdsp = NULL;
	fd_set *efdsp = NULL;
	timespec_t ts, *tsp = NULL;
	int fd_set_len = howmany(nfds, 8);
	int r;
	sigset_t sigset, *sp = NULL;

	lx_debug("\tpselect6(%d, 0x%p, 0x%p, 0x%p, 0x%p, 0x%p)",
	    p1, p2, p3, p4, p4, p6);

	if (nfds > 0) {
		if (p2 != NULL) {
			rfdsp = SAFE_ALLOCA(fd_set_len);
			if (rfdsp == NULL)
				return (-ENOMEM);
			if (uucopy((void *)p2, rfdsp, fd_set_len) != 0)
				return (-errno);
		}
		if (p3 != NULL) {
			wfdsp = SAFE_ALLOCA(fd_set_len);
			if (wfdsp == NULL)
				return (-ENOMEM);
			if (uucopy((void *)p3, wfdsp, fd_set_len) != 0)
				return (-errno);
		}
		if (p4 != NULL) {
			efdsp = SAFE_ALLOCA(fd_set_len);
			if (efdsp == NULL)
				return (-ENOMEM);
			if (uucopy((void *)p4, efdsp, fd_set_len) != 0)
				return (-errno);
		}
	}

	if (p5 != NULL) {
		if (uucopy((void *)p5, &ts, sizeof (ts)) != 0)
			return (-errno);

		tsp = &ts;
	}

	if (p6 != NULL) {
		/*
		 * To force the number of arguments to be no more than six,
		 * Linux bundles both the sigset and the size into a structure
		 * that becomes the sixth argument.
		 */
		struct {
			lx_sigset_t *addr;
			size_t size;
		} lx_sigset;

		if (uucopy((void *)p6, &lx_sigset, sizeof (lx_sigset)) != 0)
			return (-errno);

		/*
		 * Yes, that's right:  Linux forces a size to be passed only
		 * so it can check that it's the size of a sigset_t.
		 */
		if (lx_sigset.size != sizeof (lx_sigset_t))
			return (-EINVAL);

		/*
		 * This is where we check if the sigset is *really* NULL.
		 */
		if (lx_sigset.addr) {
			if ((r = ltos_sigset(lx_sigset.addr, &sigset)) != 0)
				return (r);

			sp = &sigset;
		}
	}

#if defined(_LP64)
	r = pselect(nfds, rfdsp, wfdsp, efdsp, tsp, sp);
#else
	if (nfds >= FD_SETSIZE)
		r = pselect_large_fdset(nfds, rfdsp, wfdsp, efdsp, tsp, sp);
	else
		r = pselect(nfds, rfdsp, wfdsp, efdsp, tsp, sp);
#endif

	if (r < 0)
		return (-errno);

	/*
	 * For pselect6(), we don't honor the strange Linux select() semantics
	 * with respect to the timestruc parameter because glibc ignores it
	 * anyway -- just copy out the fd pointers and return.
	 */
	if ((rfdsp != NULL) && (uucopy(rfdsp, (void *)p2, fd_set_len) != 0))
		return (-errno);
	if ((wfdsp != NULL) && (uucopy(wfdsp, (void *)p3, fd_set_len) != 0))
		return (-errno);
	if ((efdsp != NULL) && (uucopy(efdsp, (void *)p4, fd_set_len) != 0))
		return (-errno);

	return (r);
}

/*
 * The first argument is the pid (Linux tgid) to send the signal to, second
 * argument is the signal to send (an lx signal), and third is the siginfo_t
 * with extra information. We translate the code and signal only from the
 * siginfo_t, and leave everything else the same as it gets passed through the
 * signalling system. This is enough to get sigqueue working. See Linux man
 * page rt_sigqueueinfo(2).
 */
long
lx_rt_sigqueueinfo(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	pid_t tgid = (pid_t)p1;
	int lx_sig = (int)p2;
	int sig;
	lx_siginfo_t lx_siginfo;
	siginfo_t siginfo;
	int s_code;
	pid_t s_pid;

	if (uucopy((void *)p3, &lx_siginfo, sizeof (lx_siginfo_t)) != 0)
		return (-EFAULT);
	s_code = ltos_sigcode(lx_siginfo.lsi_code);
	if (s_code == LX_SI_CODE_NOT_EXIST)
		return (-EINVAL);
	if (lx_sig < 0 || lx_sig > LX_NSIG || (sig = ltos_signo[lx_sig]) < 0) {
		return (-EINVAL);
	}
	/*
	 * This case (when trying to kill pid 0) just has a different errno
	 * returned in illumos than in Linux.
	 */
	if (tgid == 0)
		return (-ESRCH);
	if (lx_lpid_to_spid(tgid, &s_pid) != 0)
		return (-ESRCH);
	if (SI_CANQUEUE(s_code)) {
		return ((syscall(SYS_sigqueue, s_pid, sig,
		    lx_siginfo.lsi_value, s_code, 0) == -1) ?
		    (-errno): 0);
	} else {
		/*
		 * This case is unlikely, as the main entry point is through
		 * sigqueue, which always has a queuable si_code.
		 */
		siginfo.si_signo = sig;
		siginfo.si_code = s_code;
		siginfo.si_pid = lx_siginfo.lsi_pid;
		siginfo.si_value = lx_siginfo.lsi_value;
		siginfo.si_uid = lx_siginfo.lsi_uid;
		return ((syscall(SYS_brand, B_HELPER_SIGQUEUE,
		    tgid, sig, &siginfo)) ? (-errno) : 0);
	}
}

/*
 * Adds an additional argument for which thread within a thread group to send
 * the signal to (added as the second argument).
 */
long
lx_rt_tgsigqueueinfo(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	pid_t tgid = (pid_t)p1;
	pid_t tid = (pid_t)p2;
	int lx_sig = (int)p3;
	int sig;
	lx_siginfo_t lx_siginfo;
	siginfo_t siginfo;
	int si_code;

	if (uucopy((void *)p4, &lx_siginfo, sizeof (lx_siginfo_t)) != 0)
		return (-EFAULT);
	if (lx_sig < 0 || lx_sig > LX_NSIG || (sig = ltos_signo[lx_sig]) < 0) {
		return (-EINVAL);
	}
	si_code = ltos_sigcode(lx_siginfo.lsi_code);
	if (si_code == LX_SI_CODE_NOT_EXIST)
		return (-EINVAL);
	/*
	 * Check for invalid tgid and tids. That appears to be only negatives
	 * and 0 values. Everything else that doesn't exist is instead ESRCH.
	 */
	if (tgid <= 0 || tid <= 0)
		return (-EINVAL);
	siginfo.si_signo = sig;
	siginfo.si_code = si_code;
	siginfo.si_pid = lx_siginfo.lsi_pid;
	siginfo.si_value = lx_siginfo.lsi_value;
	siginfo.si_uid = lx_siginfo.lsi_uid;

	return ((syscall(SYS_brand, B_HELPER_TGSIGQUEUE, tgid, tid, sig,
	    &siginfo)) ? (-errno) : 0);
}
