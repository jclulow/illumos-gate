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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Emulation of the Linux ptrace(2) interface.
 *
 * XXX This comment is not quite right -- particularly the LOCK ORDERING
 * RULES section.
 *
 * ACCORD ALLOCATION AND MANAGEMENT
 *
 * The "lx_ptrace_accord_t" struct tracks the agreement between a tracer LWP
 * and zero or more tracee LWPs.  It is explicitly illegal for a tracee to
 * trace its tracer.
 *
 * An LWP starts out without an accord.  If a child of that LWP calls ptrace(2)
 * with the PTRACE_TRACEME subcommand, or if the LWP itself uses PTRACE_ATTACH,
 * an accord will be allocated and stored on that LWP.  The accord structure is
 * not released from that LWP until it arrives in lx_exitlwp(), as called by
 * lwp_exit().  A new accord will not be allocated, even if one does not exist,
 * once an LWP arrives in lx_exitlwp() and sets "br_ptrace_exiting".  An LWP
 * will have at most one accord structure throughout its entire lifecycle, and
 * once it has one it has one until death.
 *
 * The accord is reference counted (lxpa_refcnt), starting at a count of one at
 * creation to represent the link from the tracer LWP to its accord.  The
 * accord is not freed until the reference count falls to zero.

 * A tracer LWP may attach to a presently untraced target LWP at any time using
 * PTRACE_ATTACH.  This action will induce a SIGSTOP.

 * SIGNAL MISDIRECTION
 *

 * LOCK ORDERING RULES
 *
 * 1. It is not safe, in general, to hold p_lock for two
 *    different processes at the same time.  This constraint is the primary
 *    reason for the existence (and complexity) of the accord mechanism.
 *
 * 2. In order to facilitate looking up accords by LWP "pid", p_lock for the
 *    tracer process may be held while taking the tracer accord lock
 *    (lxpa_lock).  This lock is required for reading or manipulating flags
 *    and for placing a hold on the accord structure.  It is NOT legal to
 *    take any p_lock while holding the accord lock.
 *
 * 3. 
 *
 * 4. It is NOT legal to take a tracee p_lock and then attempt to take the
 *    accord lock (lxpa_lock) of its tracer.  When running as the tracee
 *    LWP, the tracee's hold will prevent the accord from being freed.
 *
 * 5. If you need to hold both the accord lock (lxpa_lock) and sublock
 *    (lxpa_sublock), you MUST take the accord lock first and then
 *    take the sublock.
 *
 * 6. It is legal to take the accord sublock (lxpa_sublock) of an accord
 *    while holding only the p_lock of an LWP in the tracee list for that
 *    accord. (i.e. without holding the accord lock.)
 *
 * 7. It is NOT legal to take the p_lock of any tracee in the tracee list
 *    while holding the accord sublock (lxpa_sublock).
 *
 * 8. It is not safe, in general, to take "pidlock" while holding p_lock
 *    of any process.  It is similarly illegal to hold any accord locks
 *    (lxpa_lock or lxpa_sublock) while taking "pidlock".
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/sysmacros.h>
#include <sys/procfs.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/wait.h>
#include <sys/prsystm.h>

#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <sys/lx_pid.h>
#include <lx_syscall.h>
#include <lx_signum.h>


typedef enum lx_ptrace_cont_flags_t {
	LX_PTC_NONE = 0x00,
	LX_PTC_SYSCALL = 0x01,
	LX_PTC_SINGLESTEP = 0x02,
} lx_ptrace_cont_flags_t;

#define	LX_PTRACE_BUSY		(LX_PTRACE_EXITING | LX_PTRACE_STOPPING)

#define	VISIBLE(a)	(((a)->br_ptrace_flags & LX_PTRACE_EXITING) == 0)
#define	TRACEE_BUSY(a)	(((a)->br_ptrace_flags & LX_PTRACE_BUSY) != 0)

#define	ACCORD_HELD(a)	MUTEX_HELD(&(a)->lxpa_lock)

static kcondvar_t lx_ptrace_busy_cv;
static kmem_cache_t *lx_ptrace_accord_cache;

/*
 * Enter the accord mutex.
 */
static void
lx_ptrace_accord_enter(lx_ptrace_accord_t *accord)
{
	VERIFY(MUTEX_NOT_HELD(&accord->lxpa_tracees_lock));

	mutex_enter(&accord->lxpa_lock);
}

/*
 * Exit the accord mutex.  If the reference count has dropped to zero,
 * free the accord.
 */
static void
lx_ptrace_accord_exit(lx_ptrace_accord_t *accord)
{
	VERIFY(ACCORD_HELD(accord));

	if (accord->lxpa_refcnt > 0) {
		mutex_exit(&accord->lxpa_lock);
		return;
	}

	/*
	 * When the reference count drops to zero we must free the accord.
	 */
	VERIFY(accord->lxpa_tracer == NULL);
	VERIFY(MUTEX_NOT_HELD(&accord->lxpa_tracees_lock));
	VERIFY(list_is_empty(&accord->lxpa_tracees));
	VERIFY(accord->lxpa_flags & LX_ACC_TOMBSTONE);

	mutex_destroy(&accord->lxpa_lock);
	mutex_destroy(&accord->lxpa_tracees_lock);

	kmem_cache_free(lx_ptrace_accord_cache, accord);
}

/*
 * Drop our reference to this accord.  If this drops the reference count
 * to zero, the next lx_ptrace_accord_exit() will free the accord.
 */
static void
lx_ptrace_accord_rele(lx_ptrace_accord_t *accord)
{
	VERIFY(ACCORD_HELD(accord));

	VERIFY(accord->lxpa_refcnt > 0);
	accord->lxpa_refcnt--;
}

/*
 * Place an additional hold on an accord.
 */
static void
lx_ptrace_accord_hold(lx_ptrace_accord_t *accord)
{
	VERIFY(ACCORD_HELD(accord));

	accord->lxpa_refcnt++;
}


/*
 * Fetch the accord for this LWP.  If one has not yet been created, and the
 * process is not exiting, allocate it now.  Must be called with p_lock and
 * P_PR_LOCK held for the process containing the target LWP.  The accord lock
 * (lxpa_lock) is held on return.
 */
static int
lx_ptrace_accord_get_locked(klwp_t *lwp, lx_ptrace_accord_t **accordp,
    boolean_t allocate_one)
{
	lx_ptrace_accord_t *lxpa;
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	proc_t *p = lwptoproc(lwp);

	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * If this LWP does not have an accord, we wish to allocate
	 * and install one.
	 */
	if ((lxpa = lwpd->br_ptrace_accord) == NULL) {
		if (!allocate_one || !VISIBLE(lwpd)) {
			/*
			 * Either we do not wish to allocate an accord, or this
			 * LWP has already begun exiting from a ptrace
			 * perspective.
			 */
			*accordp = NULL;
			return (ESRCH);
		}

		lxpa = kmem_cache_alloc(lx_ptrace_accord_cache, KM_SLEEP);
		bzero(lxpa, sizeof (*lxpa));

		/*
		 * The initial reference count is 1 because we are referencing
		 * it in from the soon-to-be tracer LWP.
		 */
		lxpa->lxpa_refcnt = 1;
		mutex_init(&lxpa->lxpa_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&lxpa->lxpa_tracees_lock, NULL, MUTEX_DEFAULT, NULL);
		list_create(&lxpa->lxpa_tracees, sizeof (lx_lwp_data_t),
		    offsetof(lx_lwp_data_t, br_ptrace_linkage));
		lxpa->lxpa_cvp = &p->p_cv;

		lxpa->lxpa_tracer = lwpd;
		lwpd->br_ptrace_accord = lxpa;
	}

	/*
	 * Lock the accord before returning it to the caller.
	 */
	lx_ptrace_accord_enter(lxpa);

	/*
	 * There should be at least one active reference to this accord,
	 * otherwise it should have been freed.
	 */
	VERIFY(lxpa->lxpa_refcnt > 0);

	*accordp = lxpa;
	return (0);
}

/*
 * Accords belong to the tracer LWP.  Get the accord for this tracer or return
 * an error if it was not possible.  To prevent deadlocks, the caller MUST NOT
 * hold p_lock or P_PR_LOCK on its own or any other process.
 *
 * If successful, we return holding the accord lock (lxpa_lock).
 */
static int
lx_ptrace_accord_get_by_pid(pid_t lxpid, lx_ptrace_accord_t **accordp)
{
	int ret = ESRCH;
	pid_t apid;
	id_t atid;
	proc_t *aproc;
	kthread_t *athr;
	klwp_t *alwp;
	lx_lwp_data_t *alwpd;
	lx_ptrace_accord_t *lxpa;
	boolean_t tombstone;

	VERIFY(MUTEX_NOT_HELD(&curproc->p_lock));

	/*
	 * Locate the process containing the tracer LWP based on its Linux pid
	 * and lock it.
	 */
	if (lx_lpid_to_spair(lxpid, &apid, &atid) != 0 ||
	    (aproc = sprlock(apid)) == NULL) {
		return (ESRCH);
	}

	/*
	 * Locate the tracer LWP itself and ensure that it is visible to
	 * ptrace(2).
	 */
	if ((athr = idtot(aproc, atid)) == NULL ||
	    (alwp = ttolwp(athr)) == NULL ||
	    (alwpd = lwptolxlwp(alwp)) == NULL ||
	    !VISIBLE(alwpd)) {
		sprunlock(aproc);
		return (ESRCH);
	}

	/*
	 * We should not fetch our own accord this way.
	 */
	if (athr == curthread) {
		sprunlock(aproc);
		return (EPERM);
	}

	/*
	 * Fetch (or allocate) the accord owned by this tracer LWP:
	 */
	ret = lx_ptrace_accord_get_locked(alwp, accordp, B_TRUE);

	/*
	 * Unlock the process and return.
	 */
	sprunlock(aproc);
	return (ret);
}

/*
 * Get (or allocate) the ptrace(2) accord for the current LWP, acting as a
 * tracer.  The caller MUST NOT currently hold p_lock on the process containing
 * this LWP.
 *
 * If successful, we return holding the accord lock (lxpa_lock).
 */
static int
lx_ptrace_accord_get(lx_ptrace_accord_t **accordp, boolean_t allocate_one)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	int ret;

	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	/*
	 * Lock the tracer (this LWP).
	 */
	mutex_enter(&p->p_lock);

	/*
	 * Fetch (or allocate) the accord for this LWP:
	 */
	ret = lx_ptrace_accord_get_locked(lwp, accordp, allocate_one);

	mutex_exit(&p->p_lock);

	return (ret);
}

/*
 * Restart an LWP if it is in "ptrace-stop".  This function may induce sleep,
 * so do NOT hold any mutexes other than p_lock for the process containing
 * the LWP.
 */
static void
lx_ptrace_restart_lwp(klwp_t *lwp)
{
	kthread_t *rt = lwptot(lwp);
	proc_t *rproc = lwptoproc(lwp);
	lx_lwp_data_t *rlwpd = lwptolxlwp(lwp);

	VERIFY(rt != curthread);
	VERIFY(MUTEX_HELD(&rproc->p_lock));

	/*
	 * Exclude potential meddling from procfs.
	 */
	prbarrier(rproc);

	/*
	 * Check that the LWP is still in "ptrace-stop" and, if so, restart it.
	 */
	thread_lock(rt);
	if (BSTOPPED(rt) && rt->t_whystop == PR_BRANDPRIVATE) {
		rt->t_schedflag |= TS_BSTART;
		rt->t_dtrace_stop = 0;
		setrun_locked(rt);

		/*
		 * Clear stop reason.
		 */
		rlwpd->br_ptrace_whystop = 0;
		rlwpd->br_ptrace_whatstop = 0;
	}
	thread_unlock(rt);
}

static void
lx_winfo(lx_lwp_data_t *remote, k_siginfo_t *ip, boolean_t waitflag,
    pid_t *event_ppid, pid_t *event_pid)
{
	/*
	 * Populate our k_siginfo_t with data about this "ptrace-stop"
	 * condition:
	 */
	bzero(ip, sizeof (*ip));
	ip->si_signo = SIGCLD;
	ip->si_pid = remote->br_pid;
	ip->si_code = CLD_TRAPPED;

	switch (remote->br_ptrace_whatstop) {
	case LX_PR_SYSENTRY:
	case LX_PR_SYSEXIT:
		ip->si_status = SIGTRAP;
		if (remote->br_ptrace_options & LX_PTRACE_O_TRACESYSGOOD) {
			ip->si_status |= 0x80;
		}
		break;
	case LX_PR_SIGNALLED:
		/*
		 * XXX bounds check
		 */
		ip->si_status = ltos_signo[
		    (int)remote->br_ptrace_userstop];
		break;
	case LX_PR_EVENT:
		ip->si_status = SIGTRAP | remote->br_ptrace_event;
		/*
		 * Record the Linux pid of both this LWP and the create
		 * event we are dispatching.  We will use this information
		 * to unblock any subsequent ptrace(2) events that depend
		 * on this one.
		 */
		if (event_ppid != NULL)
			*event_ppid = remote->br_pid;
		if (event_pid != NULL)
			*event_pid = (pid_t)remote->br_ptrace_eventmsg;
		break;
	default:
		cmn_err(CE_PANIC, "unxpected stop subreason: %d",
		    remote->br_ptrace_whatstop);
	}

	/*
	 * If WNOWAIT was specified, do not mark the event as posted
	 * so that it may be re-fetched on another call to waitid().
	 */
	if (waitflag) {
		remote->br_ptrace_whystop = 0;
		remote->br_ptrace_whatstop = 0;
		remote->br_ptrace_flags &= ~LX_PTRACE_CLDPEND;
	}
}

/*
 * Receive notification from stop() of a PR_BRANDPRIVATE stop.
 */
void
lx_stop_notify(proc_t *p, klwp_t *lwp, ushort_t why, ushort_t what)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	lx_ptrace_accord_t *accord;
	kcondvar_t *cvp;
	klwp_t *plwp = NULL;
	proc_t *pp = NULL;
	lx_lwp_data_t *parent;
	boolean_t cldpend = B_TRUE;
	boolean_t cldpost = B_FALSE;
	sigqueue_t *sqp = NULL;

	/*
	 * We currently only care about LX-specific stop reasons.
	 */
	if (why != PR_BRANDPRIVATE)
		return;

	switch (what) {
	case LX_PR_SYSENTRY:
	case LX_PR_SYSEXIT:
	case LX_PR_SIGNALLED:
	case LX_PR_EVENT:
		break;
	default:
		cmn_err(CE_PANIC, "unexpected subreason for PR_BRANDPRIVATE"
		    " stop: %d", (int)what);
	}

	/*
	 * We should be holding the lock on our containing process.  The
	 * STOPPING flag should have been set by lx_ptrace_stop() for all
	 * PR_BRANDPRIVATE stops.
	 */
	VERIFY(MUTEX_HELD(&p->p_lock));
	VERIFY(lwpd->br_ptrace_flags & LX_PTRACE_STOPPING);
	VERIFY((accord = lwpd->br_ptrace_tracer) != NULL);

	/*
	 * We must drop our process lock to fetch the CV from the accord.
	 */
	mutex_exit(&p->p_lock);

	lx_ptrace_accord_enter(accord);
	cvp = accord->lxpa_cvp;
	parent = accord->lxpa_tracer;
	if (parent != NULL) {
		plwp = parent->br_lwp;
	}
	if (plwp != NULL) {
		pp = lwptoproc(plwp);
	}
	lx_ptrace_accord_exit(accord);

	if (pp != NULL) {
		sqp = kmem_zalloc(sizeof (*sqp), KM_SLEEP);
	}

	/*
	 * We re-take our process lock now.  The lock will then be held until
	 * the thread is actually marked stopped, so we will not race with
	 * lx_ptrace_lock_if_stopped() or lx_waitid_helper().
	 * We also take pidlock, so that we may exclude callers of waitid().
	 */
	mutex_enter(&pidlock);
	mutex_enter(&p->p_lock);

	/*
	 * Our tracer should not have been modified in our absence; the
	 * STOPPING flag prevents it.
	 */
	VERIFY(lwpd->br_ptrace_tracer == accord);

	/*
	 * Stash data for this stop condition in the LWP data while we hold
	 * both pidlock and our p_lock.
	 */
	lwpd->br_ptrace_whystop = why;
	lwpd->br_ptrace_whatstop = what;

	/*
	 * Populate the siginfo_t for the event pending on this tracee LWP.
	 */
	if (!(lwpd->br_ptrace_flags & LX_PTRACE_PARENT_WAIT) && pp != NULL) {
		cldpost = B_TRUE;
		lx_winfo(lwpd, &sqp->sq_info, B_FALSE, NULL, NULL);
	}

	/*
	 * Post the SIGCLD to the tracer.
	 */
	mutex_exit(&p->p_lock);
	if (cldpost && pp != NULL) {
		mutex_enter(&pp->p_lock);
		if (!sigismember(&pp->p_sig, SIGCLD)) {
			sigaddqa(pp, plwp->lwp_thread, sqp);
			cldpend = B_FALSE;
			sqp = NULL;
		}
		mutex_exit(&pp->p_lock);
	}
	mutex_enter(&p->p_lock);

	/*
	 * We clear the STOPPING flag; stop() continues to hold our p_lock
	 * until our thread stop state is visible.  If lx_ptrace_exit_tracer()
	 * is waiting for us to be done, we signal it here.
	 */
	lwpd->br_ptrace_flags &= ~LX_PTRACE_STOPPING;
	lwpd->br_ptrace_flags |= LX_PTRACE_STOPPED;
	if (cldpend)
		lwpd->br_ptrace_flags |= LX_PTRACE_CLDPEND;
	cv_broadcast(&lx_ptrace_busy_cv);

	/*
	 * While holding pidlock, we attempt to wake our tracer from their
	 * waitid() slumber.
	 */
	if (cvp != NULL)
		cv_broadcast(cvp);

	/*
	 * We release pidlock, and return as we were called: with our p_lock
	 * held.
	 */
	mutex_exit(&pidlock);

	if (sqp != NULL) {
		kmem_free(sqp, sizeof (*sqp));
	}
}

/*
 * For any restarting action (e.g. PTRACE_CONT, PTRACE_SYSCALL or
 * PTRACE_DETACH) to be allowed, the tracee LWP must be in "ptrace-stop".  This
 * check must ONLY be run on tracees of the current LWP.  If the check is
 * successful, we return with the tracee p_lock held.
 */
static int
lx_ptrace_lock_if_stopped(lx_ptrace_accord_t *accord, lx_lwp_data_t *remote)
{
	klwp_t *rlwp = remote->br_lwp;
	proc_t *rproc = lwptoproc(rlwp);
	kthread_t *rt = lwptot(rlwp);
	boolean_t stopped = B_FALSE;

	/*
	 * We must never check that we, ourselves, are stopped.  We must also
	 * have the accord tracee list locked while we lock our tracees.
	 */
	VERIFY(curthread != rt);
	VERIFY(MUTEX_HELD(&accord->lxpa_tracees_lock));
	VERIFY(accord->lxpa_tracer == ttolxlwp(curthread));

	/*
	 * Lock the process containing the tracee LWP.
	 */
	mutex_enter(&rproc->p_lock);
	if (!VISIBLE(remote)) {
		/*
		 * The tracee LWP is currently detaching itself as it exits.
		 * It is no longer visible to ptrace(2).
		 */
		mutex_exit(&rproc->p_lock);
		return (ESRCH);
	}

	/*
	 * We must only check whether tracees of the current LWP are stopped.
	 * We check this condition after confirming visibility as an exiting
	 * tracee may no longer be completely consistent.
	 */
	VERIFY(remote->br_ptrace_tracer == accord);

	if (!(remote->br_ptrace_flags & LX_PTRACE_STOPPED)) {
		/*
		 * The tracee is not in "ptrace-stop", so we release the
		 * process.
		 */
		mutex_exit(&rproc->p_lock);
		return (ESRCH);
	}

	/*
	 * The tracee is stopped.  We return holding its process lock so that
	 * the caller may manipulate it.
	 */
	return (0);
}

static int
lx_ptrace_setoptions(lx_lwp_data_t *remote, uintptr_t options)
{
	int error;
	lx_ptrace_accord_t *accord;

	/*
	 * Check for valid options.
	 */
	if ((options & ~LX_PTRACE_O_ALL) != 0) {
		return (EINVAL);
	}

	/*
	 * Set ptrace options on the target LWP.
	 */
	remote->br_ptrace_options = (lx_ptrace_options_t)options;

	return (0);
}

static int
lx_ptrace_geteventmsg(lx_lwp_data_t *remote, void *umsgp)
{
	int error;

#if defined(_SYSCALL32_IMPL)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		uint32_t tmp = remote->br_ptrace_eventmsg;

		error = copyout(&tmp, umsgp, sizeof (uint32_t));
	} else
#endif
	{
		error = copyout(&remote->br_ptrace_eventmsg, umsgp,
		    sizeof (ulong_t));
	}

	return (error);
}

static int
lx_ptrace_cont(lx_lwp_data_t *remote, lx_ptrace_cont_flags_t flags, int signo)
{
	int error;
	klwp_t *lwp = remote->br_lwp;

	/*
	 * The tracer may choose to supress the delivery of a signal, or select
	 * an alternative signal for delivery.  If this is an appropriate
	 * ptrace(2) "signal-stop", br_ptrace_userstop will be used as the new
	 * signal number.
	 *
	 * As with so many other aspects of the Linux ptrace(2) interface, this
	 * may also fail silently if the state machine is not aligned
	 * correctly.
	 */
	remote->br_ptrace_userstop = signo;

	/*
	 * Handle the syscall-stop flag if this is a PTRACE_SYSCALL restart:
	 */
	if (flags & LX_PTC_SYSCALL) {
		remote->br_ptrace_flags |= LX_PTRACE_SYSCALL;
	} else {
		remote->br_ptrace_flags &= ~LX_PTRACE_SYSCALL;
	}

#if 0
	/*
	 * Handle the single-step flag if this is a PTRACE_SINGLESTEP.
	 */
	mutex_exit(&rproc->p_lock);
	if (flags & LX_PTC_SINGLESTEP) {
		prstep(rlwp, 0);
	} else {
		prnostep(rlwp, 0);
	}
	mutex_enter(&rproc->p_lock);
#endif

	lx_ptrace_restart_lwp(lwp);

	return (0);
}

/*
 * Implements the PTRACE_DETACH subcommand of the Linux ptrace(2) interface.
 *
 * The LWP identified by the Linux pid "lx_pid" will, if it as a tracee of the
 * current LWP, be detached and set runnable.  If the specified LWP is not
 * currently in the "ptrace-stop" state, the routine will return ESRCH as if
 * the LWP did not exist at all.
 *
 * The caller must not hold p_lock or P_PR_LOCK on any process.
 */
static int
lx_ptrace_detach(lx_ptrace_accord_t *accord, lx_lwp_data_t *remote,
    boolean_t *release_hold)
{
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);
	boolean_t found = B_FALSE;
	boolean_t release_accord = B_TRUE;
	kthread_t *rt;
	int error;
	proc_t *rproc;
	klwp_t *rlwp;

	rlwp = remote->br_lwp;
	rproc = lwptoproc(rlwp);

	/*
	 * The tracee LWP was in "ptrace-stop" and we now hold its p_lock.
	 * Detach the LWP from the accord and set it running.
	 */
	VERIFY(!TRACEE_BUSY(remote));
	remote->br_ptrace_flags &= ~(LX_PTRACE_SYSCALL | LX_PTRACE_INHERIT);
	VERIFY(list_link_active(&remote->br_ptrace_linkage));
	list_remove(&accord->lxpa_tracees, remote);

	remote->br_ptrace_attach = LX_PTA_NONE;
	remote->br_ptrace_tracer = NULL;
	remote->br_ptrace_flags = 0;
	*release_hold = B_TRUE;

	lx_ptrace_restart_lwp(rlwp);

	return (0);
}


/*
 * This routine implements the PTRACE_ATTACH operation of the Linux ptrace(2)
 * interface.
 *
 * This LWP is requesting to be attached as a tracer to another LWP -- the
 * tracee.  If a ptrace accord to track the list of tracees has not yet been
 * allocated, one will be allocated and attached to this LWP now.
 *
 * The "br_ptrace_tracer" on the tracee LWP is set to this accord, and the
 * tracee LWP is then added to the "lxpa_tracees" list in the accord.  We drop
 * locks between these two phases; the only consumer of trace events from this
 * accord is this LWP, which obviously cannot be running waitpid(2) at the same
 * time as this call to ptrace(2).
 */
static int
lx_ptrace_attach(pid_t lx_pid)
{
	int error = ESRCH;
	int32_t one = 1;
	/*
	 * Our (Tracer) LWP:
	 */
	lx_ptrace_accord_t *accord;
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);
	/*
	 * Remote (Tracee) LWP:
	 */
	pid_t rpid;
	id_t rtid;
	proc_t *rproc;
	kthread_t *rthr;
	klwp_t *rlwp;
	lx_lwp_data_t *rlwpd;
	lx_proc_data_t *rprocd;

	if (lwpd->br_pid == lx_pid) {
		/*
		 * We cannot trace ourselves.
		 */
		return (EPERM);
	}

	/*
	 * Ensure that we have an accord and obtain a lock on it.  This
	 * routine should not fail because the LWP cannot make ptrace(2) system
	 * calls after it has begun exiting.
	 */
	VERIFY0(lwpd->br_ptrace_flags & LX_PTRACE_EXITING);
	VERIFY(lx_ptrace_accord_get(&accord, B_TRUE) == 0);

	/*
	 * Place speculative hold in case the attach is successful.
	 */
	lx_ptrace_accord_hold(accord);
	lx_ptrace_accord_exit(accord);

	/*
	 * Locate the process containing the tracee LWP based on its Linux pid
	 * and lock it.
	 */
	if (lx_lpid_to_spair(lx_pid, &rpid, &rtid) != 0 ||
	    (rproc = sprlock(rpid)) == NULL) {
		/*
		 * We could not find the target process.
		 */
		return (ESRCH);
	}

	/*
	 * Locate the tracee LWP.
	 */
	if ((rthr = idtot(rproc, rtid)) == NULL ||
	    (rlwp = ttolwp(rthr)) == NULL ||
	    (rlwpd = lwptolxlwp(rlwp)) == NULL ||
	    !VISIBLE(rlwpd)) {
		/*
		 * The LWP could not be found, was not branded, or is not
		 * visible to ptrace(2) at this time.
		 */
		sprunlock(rproc);
		return (ESRCH);
	}

	/*
	 * We now hold the lock on the tracee.  Attempt to install ourselves
	 * as the tracer.
	 */
	if (curproc != rproc && priv_proc_cred_perm(curproc->p_cred, rproc,
	    NULL, VWRITE) != 0) {
		/*
		 * This process does not have permission to trace the remote
		 * process.
		 */
		error = EPERM;
	} else if (rlwpd->br_ptrace_tracer != NULL) {
		/*
		 * This LWP is already being traced.
		 */
		VERIFY(list_link_active(&rlwpd->br_ptrace_linkage));
		error = EPERM;
	} else {
		/*
		 * Bond the tracee to the accord.
		 */
		VERIFY0(rlwpd->br_ptrace_flags & LX_PTRACE_EXITING);
		rlwpd->br_ptrace_attach = LX_PTA_ATTACH;
		rlwpd->br_ptrace_tracer = accord;

		/*
		 * We had no tracer, and are thus not in the tracees list.
		 * It is safe to take the tracee list lock while we insert
		 * ourselves.
		 */
		mutex_enter(&accord->lxpa_tracees_lock);
		VERIFY(!list_link_active(&rlwpd->br_ptrace_linkage));
		list_insert_tail(&accord->lxpa_tracees, rlwpd);
		mutex_exit(&accord->lxpa_tracees_lock);

		/*
		 * Send a thread-directed SIGSTOP.
		 */
		sigtoproc(rproc, rthr, SIGSTOP);
		error = 0;
	}

	/*
	 * Set the in-kernel process-wide ptrace(2) enable flag.  Attempt also
	 * to write the usermode trace flag so that the process knows to enter
	 * the kernel for potential ptrace(2) syscall-stops.
	 */
	rprocd = ttolxproc(rthr);
	rprocd->l_ptrace = 1;
	mutex_exit(&rproc->p_lock);
	(void) uwrite(rproc, &one, sizeof (one), rprocd->l_traceflag);
	mutex_enter(&rproc->p_lock);

	/*
	 * Unlock the process containing the tracee LWP and the accord.
	 */
	sprunlock(rproc);

	if (error != 0) {
		/*
		 * The attach was not successful.  Remove our speculative
		 * hold.
		 */
		lx_ptrace_accord_enter(accord);
		lx_ptrace_accord_rele(accord);
		lx_ptrace_accord_exit(accord);
	}

	return (error);
}

int
lx_ptrace_set_clone_inherit(boolean_t inherit)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);

	mutex_enter(&p->p_lock);

	if (inherit) {
		lwpd->br_ptrace_flags |= LX_PTRACE_INHERIT;
	} else {
		lwpd->br_ptrace_flags &= ~LX_PTRACE_INHERIT;
	}

	mutex_exit(&p->p_lock);
	return (0);
}

/*
 * If the parent LWP is being traced, we want to attach ourselves to the
 * same accord.
 */
void
lx_ptrace_inherit_tracer(lx_lwp_data_t *src, lx_lwp_data_t *dst)
{
	lx_ptrace_accord_t *accord;

	/*
	 * XXX probably need to _lock_ the traced process until we can get a
	 * hold on the accord.
	 */
#if 0
	if ((accord = src->br_ptrace_tracer) == NULL ||
	    !(src->br_ptrace_flags & LX_PTRACE_INHERIT)) {
	}
#endif
	if ((accord = src->br_ptrace_tracer) == NULL) {
		/*
		 * Either the source LWP does not have a tracer to inherit,
		 * or PTRACE_CLONE was not used in the current clone()
		 * operation.
		 */
		return;
	}

	/*
	 * XXX should handle this properly.
	 */
	if (!src->br_ptrace_options) {
		return;
	}

	/*
	 * We can be somewhat lax with locking, here.  The destination LWP is
	 * not yet running, and we _are_ the source LWP.
	 */

	/*
	 * Hold the accord for the new LWP.
	 */
	lx_ptrace_accord_enter(accord);
	lx_ptrace_accord_hold(accord);
	lx_ptrace_accord_exit(accord);

	dst->br_ptrace_attach = LX_PTA_INHERIT_OPTIONS;
	dst->br_ptrace_tracer = accord;

	/*
	 * This flag prevents waitid() from seeing events for the new child
	 * until the parent is able to post the relevant ptrace event to
	 * the tracer.
	 *
	 * XXX this should presumably only happen as part of, e.g.
	 * PTRACE_O_TRACECLONE.  Perhaps not as part of the CLONE_PTRACE
	 * flag to clone(2)?
	 */
	dst->br_ptrace_flags |= LX_PTRACE_PARENT_WAIT;

	mutex_enter(&accord->lxpa_tracees_lock);
	VERIFY(list_link_active(&src->br_ptrace_linkage));
	VERIFY(!list_link_active(&dst->br_ptrace_linkage));
	list_insert_tail(&accord->lxpa_tracees, dst);
	mutex_exit(&accord->lxpa_tracees_lock);

	/*
	 * This flag only lasts for the duration of a single clone.
	 */
	src->br_ptrace_flags &= ~LX_PTRACE_INHERIT;

	/*
	 * XXX Just copy trace options for now...
	 */
	dst->br_ptrace_options = src->br_ptrace_options;
}

static int
lx_ptrace_traceme(void)
{
	int error;
	boolean_t did_attach = B_FALSE;
	/*
	 * Our (Tracee) LWP:
	 */
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	/*
	 * Remote (Tracer) LWP:
	 */
	pid_t lx_ppid;
	pid_t rpid;
	id_t rtid;
	lx_ptrace_accord_t *accord;

	/*
	 * We are intending to be the tracee.  Fetch (or allocate) the accord
	 * for our parent LWP.
	 */
	if ((error = lx_ptrace_accord_get_by_pid(lx_lwp_ppid(lwp, NULL,
	    NULL), &accord)) != 0) {
		/*
		 * Could not determine the Linux pid of the parent LWP, or
		 * could not get the accord for that LWP.
		 */
		return (error);
	}

	/*
	 * We now hold the accord lock.
	 */
	if (accord->lxpa_flags & LX_ACC_TOMBSTONE) {
		/*
		 * The accord is marked for death; give up now.
		 */
		lx_ptrace_accord_exit(accord);
		return (ESRCH);
	}

	/*
	 * Bump the reference count so that the accord is not freed.  We need
	 * to drop the accord lock before we take our own p_lock.
	 */
	lx_ptrace_accord_hold(accord);
	lx_ptrace_accord_exit(accord);

	/*
	 * We now lock _our_ process and determine if we can install our parent
	 * as our tracer.
	 */
	mutex_enter(&p->p_lock);
	if (lwpd->br_ptrace_tracer != NULL) {
		/*
		 * This LWP is already being traced.
		 */
		error = EPERM;
	} else {
		/*
		 * Bond ourselves to the accord.  We already bumped the accord
		 * reference count.
		 */
		lwpd->br_ptrace_attach = LX_PTA_TRACEME;
		lwpd->br_ptrace_tracer = accord;
		did_attach = B_TRUE;
		error = 0;
	}
	mutex_exit(&p->p_lock);

	/*
	 * Lock the accord tracee list and add this LWP.  Once we are in the
	 * tracee list, it is the responsibility of the tracer to detach us.
	 */
	if (error == 0) {
		lx_ptrace_accord_enter(accord);
		mutex_enter(&accord->lxpa_tracees_lock);

		if (!(accord->lxpa_flags & LX_ACC_TOMBSTONE)) {
			/*
			 * Put ourselves in the tracee list for this accord
			 * and return success to the caller.
			 */
			VERIFY(!list_link_active(&lwpd->br_ptrace_linkage));
			list_insert_tail(&accord->lxpa_tracees, lwpd);
			mutex_exit(&accord->lxpa_tracees_lock);
			lx_ptrace_accord_exit(accord);
			return (0);
		}
		mutex_exit(&accord->lxpa_tracees_lock);

		/*
		 * The accord has been marked for death.  We must
		 * untrace ourselves.
		 */
		error = ESRCH;
		lx_ptrace_accord_exit(accord);
	}

	/*
	 * Our optimism was unjustified: We were unable to attach.  We need to
	 * lock the process containing this LWP again in order to remove the
	 * tracer.
	 */
	VERIFY(error != 0);
	mutex_enter(&p->p_lock);
	if (did_attach) {
		/*
		 * Verify that things were as we left them:
		 */
		VERIFY(!list_link_active(&lwpd->br_ptrace_linkage));
		VERIFY(lwpd->br_ptrace_tracer == accord);

		lwpd->br_ptrace_attach = LX_PTA_NONE;
		lwpd->br_ptrace_tracer = NULL;
	}
	mutex_exit(&p->p_lock);

	/*
	 * Remove our speculative hold on the accord, possibly causing it to be
	 * freed in the process.
	 */
	lx_ptrace_accord_enter(accord);
	lx_ptrace_accord_rele(accord);
	lx_ptrace_accord_exit(accord);

	return (error);
}

static boolean_t
lx_ptrace_stop_common(klwp_t *lwp, proc_t *p, lx_lwp_data_t *lwpd,
    ushort_t what)
{
	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * Mark this LWP as stopping and call stop() to enter "ptrace-stop".
	 */
	VERIFY0(lwpd->br_ptrace_flags & LX_PTRACE_STOPPING);
	lwpd->br_ptrace_flags |= LX_PTRACE_STOPPING;
	stop(PR_BRANDPRIVATE, what);

	/*
	 * We are back from "ptrace-stop" with our process lock held.
	 */
	lwpd->br_ptrace_flags &= ~(LX_PTRACE_STOPPING | LX_PTRACE_STOPPED |
	    LX_PTRACE_CLDPEND);
	cv_broadcast(&lx_ptrace_busy_cv);
	mutex_exit(&p->p_lock);

	return (B_TRUE);
}

int
lx_ptrace_stop_for_option(int option, boolean_t child, ulong_t msg)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	lx_ptrace_accord_t *accord;

	mutex_enter(&p->p_lock);
	if (lwpd->br_ptrace_tracer == NULL) {
		mutex_exit(&p->p_lock);
		return (ESRCH);
	}

	if (!(lwpd->br_ptrace_options & option)) {
		if (option == LX_PTRACE_O_TRACEEXEC) {
			/*
			 * Without PTRACE_O_TRACEEXEC, the Linux kernel will
			 * send SIGTRAP to the process.
			 */
			sigtoproc(p, t, SIGTRAP);
			mutex_exit(&p->p_lock);
			return (0);
		}

		/*
		 * The flag for this trace event is not enabled, so we will not
		 * stop.
		 */
		mutex_exit(&p->p_lock);
		return (ESRCH);
	}

	if (child) {
		switch (option) {
		case LX_PTRACE_O_TRACECLONE:
		case LX_PTRACE_O_TRACEFORK:
		case LX_PTRACE_O_TRACEVFORK:
			/*
			 * Send the child LWP a directed SIGSTOP.
			 */
			sigtoproc(p, t, SIGSTOP);
			mutex_exit(&p->p_lock);
			return (ESRCH);
		default:
			goto nostop;
		}
	}

	lwpd->br_ptrace_eventmsg = msg;

	switch (option) {
	case LX_PTRACE_O_TRACECLONE:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_CLONE;
		break;
	case LX_PTRACE_O_TRACEEXEC:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_EXEC;
		lwpd->br_ptrace_eventmsg = 0;
		break;
	case LX_PTRACE_O_TRACEEXIT:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_EXIT;
		break;
	case LX_PTRACE_O_TRACEFORK:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_FORK;
		break;
	case LX_PTRACE_O_TRACEVFORK:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_VFORK;
		break;
	case LX_PTRACE_O_TRACEVFORKDONE:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_VFORK_DONE;
		lwpd->br_ptrace_eventmsg = 0;
		break;
	default:
		goto nostop;
	}

	return (lx_ptrace_stop_common(lwp, p, lwpd, LX_PR_EVENT) ? 0 : ESRCH);

nostop:
	lwpd->br_ptrace_event = 0;
	lwpd->br_ptrace_eventmsg = 0;
	mutex_exit(&p->p_lock);
	return (ESRCH);
}

boolean_t
lx_ptrace_stop(ushort_t what)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	lx_ptrace_accord_t *accord;
	boolean_t trace = B_TRUE;

	VERIFY(what == LX_PR_SYSENTRY || what == LX_PR_SYSEXIT ||
	    what == LX_PR_SIGNALLED);

	/*
	 * If we do not have an accord, bail out early.
	 */
	if (lwpd->br_ptrace_tracer == NULL)
		return (B_FALSE);

	/*
	 * Lock this process and re-check the condition.
	 */
	mutex_enter(&p->p_lock);
	if (lwpd->br_ptrace_tracer == NULL) {
		VERIFY0(lwpd->br_ptrace_flags & LX_PTRACE_SYSCALL);
		mutex_exit(&p->p_lock);
		return (B_FALSE);
	}

	if (what == LX_PR_SYSENTRY || what == LX_PR_SYSEXIT) {
		/*
		 * This is a syscall-entry-stop or syscall-exit-stop point.
		 */
		if (!(lwpd->br_ptrace_flags & LX_PTRACE_SYSCALL)) {
			/*
			 * A system call stop has not been requested.
			 */
			mutex_exit(&p->p_lock);
			return (B_FALSE);
		}

		/*
		 * The PTRACE_SYSCALL restart command applies only to the next
		 * system call entry or exit.  The tracer must restart us with
		 * PTRACE_SYSCALL while we are in ptrace-stop for us to fire
		 * again at the next system call boundary.
		 */
		lwpd->br_ptrace_flags &= ~LX_PTRACE_SYSCALL;
	}

	return (lx_ptrace_stop_common(lwp, p, lwpd, what));
}

int
lx_issig_stop(proc_t *p, klwp_t *lwp)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	int lx_sig;

	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * If we do not have an accord, bail out now.  Additionally, if there
	 * is no valid signal then we have no reason to stop.
	 */
	if (lwpd->br_ptrace_tracer == NULL || lwp->lwp_cursig == SIGKILL ||
	    (lwp->lwp_cursig == 0 || lwp->lwp_cursig > NSIG) ||
	    (lx_sig = stol_signo[lwp->lwp_cursig]) < 1) {
		return (0);
	}

	/*
	 * We stash the signal on the LWP where our waitid_helper will find it
	 * and enter the ptrace "signal-delivery-stop" condition.
	 */
	lwpd->br_ptrace_userstop = lx_sig;
	(void) lx_ptrace_stop_common(lwp, p, lwpd, LX_PR_SIGNALLED);
	mutex_enter(&p->p_lock);

	/*
	 * When we return, the signal may have been altered or suppressed.
	 */
	if (lwpd->br_ptrace_userstop != lx_sig) {
		int native_sig;
		lx_sig = lwpd->br_ptrace_userstop;

		if (lx_sig >= LX_NSIG) {
			lx_sig = 0;
		}

		/*
		 * Translate signal from Linux signal number back to
		 * an illumos native signal.
		 */
		if (lx_sig >= LX_NSIG || lx_sig < 0 || (native_sig =
		    ltos_signo[lx_sig]) < 1) {
			/*
			 * The signal is not deliverable.
			 */
			lwp->lwp_cursig = 0;
			lwp->lwp_extsig = 0;
			if (lwp->lwp_curinfo) {
				siginfofree(lwp->lwp_curinfo);
				lwp->lwp_curinfo = NULL;
			}
		} else {
			/*
			 * Alter the currently dispatching signal.
			 */
			if (native_sig == SIGKILL) {
				/*
				 * We mark ourselves the victim and request
				 * a restart of signal processing.
				 */
				p->p_flag |= SKILLED;
				p->p_flag &= ~SEXTKILLED;
				return (-1);
			}
			lwp->lwp_cursig = native_sig;
			lwp->lwp_extsig = 0;
			if (lwp->lwp_curinfo != NULL) {
				lwp->lwp_curinfo->sq_info.si_signo = native_sig;
			}
		}
	}

	lwpd->br_ptrace_userstop = 0;
	return (0);
}

static void
lx_ptrace_exit_tracer(proc_t *p, lx_lwp_data_t *lwpd,
    lx_ptrace_accord_t *accord)
{
	int ret;

	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	lx_ptrace_accord_enter(accord);
	/*
	 * Mark this accord for death.  This means no new tracees can be
	 * attached to this accord.
	 */
	VERIFY0(accord->lxpa_flags & LX_ACC_TOMBSTONE);
	accord->lxpa_flags |= LX_ACC_TOMBSTONE;
	lx_ptrace_accord_exit(accord);

again:
	/*
	 * Walk the list of tracees, detaching them and setting them runnable
	 * if they are stopped.
	 */
	for (;;) {
		klwp_t *rlwp;
		proc_t *rproc;
		lx_lwp_data_t *remote;
		kmutex_t *rmp;

		mutex_enter(&accord->lxpa_tracees_lock);
		if (list_is_empty(&accord->lxpa_tracees)) {
			mutex_exit(&accord->lxpa_tracees_lock);
			break;
		}

		/*
		 * Fetch the first tracee LWP in the list and lock the process
		 * which contains it.
		 */
		remote = list_head(&accord->lxpa_tracees);
		rlwp = remote->br_lwp;
		rproc = lwptoproc(rlwp);
		/*
		 * The p_lock mutex persists beyond the life of the process
		 * itself.  We save the address, here, to prevent the need to
		 * dereference the proc_t after awaking from sleep.
		 */
		rmp = &rproc->p_lock;
		mutex_enter(rmp);

		if (TRACEE_BUSY(remote)) {
			/*
			 * This LWP is currently detaching itself on exit, or
			 * mid-way through stop().  We must wait for this
			 * action to be completed.  While we wait on the CV, we
			 * must drop the accord tracee list lock.
			 */
			mutex_exit(&accord->lxpa_tracees_lock);
			cv_wait(&lx_ptrace_busy_cv, rmp);

			/*
			 * While we were waiting, some state may have changed.
			 * Restart the walk to be sure we don't miss anything.
			 */
			mutex_exit(rmp);
			continue;
		}

		/*
		 * We now hold p_lock on the process.  Remove the tracee from
		 * the list.
		 */
		VERIFY(list_link_active(&remote->br_ptrace_linkage));
		list_remove(&accord->lxpa_tracees, remote);

		/*
		 * Unlink the accord and clear our trace flags.
		 */
		remote->br_ptrace_attach = LX_PTA_NONE;
		remote->br_ptrace_tracer = NULL;
		remote->br_ptrace_flags = 0;

		/*
		 * Let go of the list lock before we restart the LWP.  We must
		 * not hold any locks other than the process p_lock when
		 * we call lx_ptrace_restart_lwp() as it will thread_lock
		 * the tracee.
		 */
		mutex_exit(&accord->lxpa_tracees_lock);

		/*
		 * Ensure that the LWP is not stopped on our account.
		 */
		lx_ptrace_restart_lwp(rlwp);

		/*
		 * Unlock the former tracee.
		 */
		mutex_exit(rmp);

		/*
		 * Drop the hold this tracee had on the accord.
		 */
		lx_ptrace_accord_enter(accord);
		lx_ptrace_accord_rele(accord);
		lx_ptrace_accord_exit(accord);
	}

	mutex_enter(&p->p_lock);
	lwpd->br_ptrace_accord = NULL;
	mutex_exit(&p->p_lock);

	/*
	 * Clean up and release our hold on the accord If we completely
	 * detached all tracee LWPs, this will free the accord.  Otherwise, it
	 * will be freed when they complete their cleanup.
	 */
	lx_ptrace_accord_enter(accord);
	accord->lxpa_cvp = NULL;
	accord->lxpa_tracer = NULL;
	lx_ptrace_accord_rele(accord);
	lx_ptrace_accord_exit(accord);
}

static void
lx_ptrace_exit_tracee(proc_t *p, lx_lwp_data_t *lwpd,
    lx_ptrace_accord_t *accord)
{
	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	/*
	 * We are the tracee LWP.  Lock the accord tracee list and then our
	 * containing process.
	 */
	mutex_enter(&accord->lxpa_tracees_lock);
	mutex_enter(&p->p_lock);

	/*
	 * Remove our reference to the accord.  We will release our hold
	 * later.
	 */
	VERIFY(lwpd->br_ptrace_tracer == accord);
	lwpd->br_ptrace_attach = LX_PTA_NONE;
	lwpd->br_ptrace_tracer = NULL;

	/*
	 * Remove this LWP from the accord tracee list:
	 */
	VERIFY(list_link_active(&lwpd->br_ptrace_linkage));
	list_remove(&accord->lxpa_tracees, lwpd);

	/*
	 * Wake up any tracers waiting for us to detach from the accord.
	 */
	cv_broadcast(&lx_ptrace_busy_cv);
	mutex_exit(&p->p_lock);
	mutex_exit(&accord->lxpa_tracees_lock);

	/*
	 * Release our hold on the accord.
	 */
	lx_ptrace_accord_enter(accord);
	lx_ptrace_accord_rele(accord);
	lx_ptrace_accord_exit(accord);
}

/*
 * This routine is called from lx_exitlwp() when an LWP is ready to exit.  If
 * this LWP is being traced, it will be detached from the tracer's accord.  The
 * routine will also detach any LWPs being traced by this LWP.
 */
void
lx_ptrace_exit(proc_t *p, klwp_t *lwp)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	lx_ptrace_accord_t *accord;

	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * Mark our LWP as exiting from a ptrace perspective.  This will
	 * prevent a new accord from being allocated if one does not exist
	 * already, and will make us invisible to PTRACE_ATTACH/PTRACE_TRACEME.
	 */
	VERIFY0(lwpd->br_ptrace_flags & LX_PTRACE_EXITING);
	lwpd->br_ptrace_flags |= LX_PTRACE_EXITING;

	if ((accord = lwpd->br_ptrace_tracer) != NULL) {
		/*
		 * We are traced by another LWP and must detach ourselves.
		 */
		mutex_exit(&p->p_lock);
		lx_ptrace_exit_tracee(p, lwpd, accord);
		mutex_enter(&p->p_lock);
	}

	if ((accord = lwpd->br_ptrace_accord) != NULL) {
		/*
		 * We have been tracing other LWPs, and must detach from
		 * them and clean up our accord.
		 */
		mutex_exit(&p->p_lock);
		lx_ptrace_exit_tracer(p, lwpd, accord);
		mutex_enter(&p->p_lock);
	}
}

/*
 * Called when a SIGCLD signal is dispatched so that we may enqueue another.
 * Return 0 if we enqueued a signal, or -1 if not.
 */
int
lx_sigcld_repost(proc_t *pp, sigqueue_t *sqp)
{
	klwp_t *lwp = ttolwp(curthread);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	lx_ptrace_accord_t *accord;
	lx_lwp_data_t *remote;
	klwp_t *rlwp;
	proc_t *rproc;
	boolean_t found = B_FALSE;

	VERIFY(MUTEX_HELD(&pidlock));
	VERIFY(MUTEX_NOT_HELD(&pp->p_lock));
	VERIFY(lwptoproc(lwp) == pp);

	mutex_enter(&pp->p_lock);
	if ((accord = lwpd->br_ptrace_accord) == NULL) {
		/*
		 * This LWP is not a tracer LWP, so there will be no
		 * SIGCLD.
		 */
		mutex_exit(&pp->p_lock);
		return (-1);
	}
	mutex_exit(&pp->p_lock);

	mutex_enter(&accord->lxpa_tracees_lock);
	for (remote = list_head(&accord->lxpa_tracees); remote != NULL;
	    remote = list_next(&accord->lxpa_tracees, remote)) {
		rlwp = remote->br_lwp;
		rproc = lwptoproc(rlwp);

		/*
		 * Check if this LWP is in "ptrace-stop".  If in the correct
		 * stop condition, lock the process containing the tracee LWP.
		 */
		if (lx_ptrace_lock_if_stopped(accord, remote) != 0) {
			continue;
		}

		if (remote->br_ptrace_flags & LX_PTRACE_PARENT_WAIT) {
			/*
			 * This event depends on waitid() clearing out the
			 * event of another LWP.  Skip it for now.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		if (!(remote->br_ptrace_flags & LX_PTRACE_CLDPEND)) {
			/*
			 * No SIGCLD is required for this LWP.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		if (remote->br_ptrace_whystop == 0 ||
		    remote->br_ptrace_whatstop == 0) {
			/*
			 * No (new) stop reason to post for this LWP.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		/*
		 * We found a process of interest.  Leave the process
		 * containing the tracee LWP locked and break out of the loop.
		 */
		found = B_TRUE;
		break;
	}
	mutex_exit(&accord->lxpa_tracees_lock);

	if (!found) {
		return (-1);
	}

	/*
	 * Generate siginfo for this tracee LWP.
	 */
	lx_winfo(remote, &sqp->sq_info, B_FALSE, NULL, NULL);
	remote->br_ptrace_flags &= ~LX_PTRACE_CLDPEND;
	mutex_exit(&rproc->p_lock);

	mutex_enter(&pp->p_lock);
	if (sigismember(&pp->p_sig, SIGCLD)) {
		mutex_exit(&pp->p_lock);

		mutex_enter(&rproc->p_lock);
		remote->br_ptrace_flags |= LX_PTRACE_CLDPEND;
		mutex_exit(&rproc->p_lock);

		return (-1);
	}
	sigaddqa(pp, curthread, sqp);
	mutex_exit(&pp->p_lock);

	return (0);
}

/*
 * Consume the next available ptrace(2) event queued against the accord for
 * this LWP.  The event will be emitted as if through waitid(), and converted
 * by lx_waitpid() and friends before the return to usermode.
 */
int
lx_waitid_helper(idtype_t idtype, id_t id, k_siginfo_t *ip, int options,
    boolean_t *brand_wants_wait, int *rval)
{
	lx_ptrace_accord_t *accord;
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *local = lwptolxlwp(lwp);
	lx_lwp_data_t *remote;
	boolean_t found = B_FALSE;
	klwp_t *rlwp = NULL;
	proc_t *rproc = NULL;
	pid_t event_pid = 0, event_ppid = 0;
	boolean_t waitflag = !(options & WNOWAIT);

	VERIFY(MUTEX_HELD(&pidlock));
	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	/*
	 * By default, we do not expect waitid() to block on our account.
	 */
	*brand_wants_wait = B_FALSE;

	if (!local->br_waitid_emulate) {
		/*
		 * This waitid() call is not expecting emulated results.
		 */
		return (-1);
	}

	switch (idtype) {
	case P_ALL:
	case P_PID:
	case P_PGID:
		break;
	default:
		/*
		 * This idtype has no power here.
		 */
		return (-1);
	}

	if (lx_ptrace_accord_get(&accord, B_FALSE) != 0) {
		/*
		 * This LWP does not have an accord; it cannot be tracing.
		 */
		return (-1);
	}

	/*
	 * We do not need an additional hold on the accord as it belongs to
	 * the running, tracer, LWP.
	 */
	lx_ptrace_accord_exit(accord);

	mutex_enter(&accord->lxpa_tracees_lock);
	if (list_is_empty(&accord->lxpa_tracees)) {
		/*
		 * Though it has an accord, there are currently no tracees in
		 * the list for this LWP.
		 */
		mutex_exit(&accord->lxpa_tracees_lock);
		return (-1);
	}

	/*
	 * Walk the list of tracees and determine if any of them have events to
	 * report.
	 */
	for (remote = list_head(&accord->lxpa_tracees); remote != NULL;
	    remote = list_next(&accord->lxpa_tracees, remote)) {
		rlwp = remote->br_lwp;
		rproc = lwptoproc(rlwp);

		/*
		 * Check to see if this LWP matches an id we are waiting for.
		 */
		switch (idtype) {
		case P_ALL:
			break;
		case P_PID:
			if (remote->br_pid != id)
				continue;
			break;
		case P_PGID:
			if (rproc->p_pgrp != id)
				continue;
			break;
		default:
			cmn_err(CE_PANIC, "unexpected idtype: %d", idtype);
		}

		/*
		 * Check if this LWP is in "ptrace-stop".  If in the correct
		 * stop condition, lock the process containing the tracee LWP.
		 */
		if (lx_ptrace_lock_if_stopped(accord, remote) != 0) {
			continue;
		}

		if (remote->br_ptrace_flags & LX_PTRACE_PARENT_WAIT) {
			/*
			 * This event depends on waitid() clearing out the
			 * event of another LWP.  Skip it for now.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		if (remote->br_ptrace_whystop == 0 ||
		    remote->br_ptrace_whatstop == 0) {
			/*
			 * No (new) stop reason to post for this LWP.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		/*
		 * We found a process of interest.  Leave the process
		 * containing the tracee LWP locked and break out of the loop.
		 */
		found = B_TRUE;
		break;
	}
	mutex_exit(&accord->lxpa_tracees_lock);

	if (!found) {
		/*
		 * There were no events of interest, but we have tracees.
		 * Signal to waitid() that it should block if the provided
		 * flags allow for it.
		 */
		*brand_wants_wait = B_TRUE;
		return (-1);
	}

	/*
	 * Populate the signal information.
	 */
	lx_winfo(remote, ip, waitflag, &event_ppid, &event_pid);

	/*
	 * Unlock the tracee.
	 */
	mutex_exit(&rproc->p_lock);

	if (event_pid != 0 && event_ppid != 0) {
		/*
		 * We need to do another pass around the tracee list and
		 * unblock any events that have a "happens after" relationship
		 * with this event.
		 */
		mutex_enter(&accord->lxpa_tracees_lock);
		for (remote = list_head(&accord->lxpa_tracees); remote != NULL;
		    remote = list_next(&accord->lxpa_tracees, remote)) {
			rlwp = remote->br_lwp;
			rproc = lwptoproc(rlwp);

			mutex_enter(&rproc->p_lock);

			if (remote->br_pid != event_pid ||
			    remote->br_ppid != event_ppid) {
				mutex_exit(&rproc->p_lock);
				continue;
			}

			remote->br_ptrace_flags &= ~LX_PTRACE_PARENT_WAIT;

			mutex_exit(&rproc->p_lock);
		}
		mutex_exit(&accord->lxpa_tracees_lock);
	}

	/*
	 * If we are consuming this wait state, we remove the SIGCLD from
	 * the queue and post another.
	 */
	if (waitflag) {
		sigqueue_t *sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);

		sigcld_delete(ip);
		if (lx_sigcld_repost(p, sqp) != 0) {
			kmem_free(sqp, sizeof (sigqueue_t));
		}
	}

	*rval = 0;
	return (0);
}

/*
 * Some PTRACE_* requests are handled in-kernel by this function.
 */
int
lx_ptrace_kernel(int ptrace_op, pid_t lxpid, uintptr_t addr, uintptr_t data)
{
	lx_lwp_data_t *local = ttolxlwp(curthread);
	lx_ptrace_accord_t *accord;
	lx_lwp_data_t *remote;
	klwp_t *rlwp;
	proc_t *rproc;
	int error;
	boolean_t found = B_FALSE;
	boolean_t release_hold = B_FALSE;

	/*
	 * These actions do not require the target LWP to be traced or stopped.
	 */
	switch (ptrace_op) {
	case LX_PTRACE_TRACEME:
		return (lx_ptrace_traceme());

	case LX_PTRACE_ATTACH:
		return (lx_ptrace_attach(lxpid));
	}

	/*
	 * Ensure that we have an accord and obtain a lock on it.  This routine
	 * should not fail because the LWP cannot make ptrace(2) system calls
	 * after it has begun exiting.
	 */
	VERIFY0(local->br_ptrace_flags & LX_PTRACE_EXITING);
	VERIFY(lx_ptrace_accord_get(&accord, B_TRUE) == 0);

	/*
	 * The accord belongs to this, the tracer, LWP.  We drop the lock so
	 * that we can take other locks.
	 */
	lx_ptrace_accord_exit(accord);

	/*
	 * Does the tracee list contain the pid in question?
	 */
	mutex_enter(&accord->lxpa_tracees_lock);
	for (remote = list_head(&accord->lxpa_tracees); remote != NULL;
	    remote = list_next(&accord->lxpa_tracees, remote)) {
		if (remote->br_pid == lxpid) {
			found = B_TRUE;
			break;
		}
	}
	if (!found) {
		/*
		 * The requested pid does not appear in the tracee list.
		 */
		mutex_exit(&accord->lxpa_tracees_lock);
		return (ESRCH);
	}

	/*
	 * Attempt to lock the target LWP.
	 */
	if ((error = lx_ptrace_lock_if_stopped(accord, remote)) != 0) {
		/*
		 * The LWP was not in "ptrace-stop".
		 */
		mutex_exit(&accord->lxpa_tracees_lock);
		return (error);
	}

	/*
	 * The target LWP is in "ptrace-stop".  We have the containing process
	 * locked.
	 */
	rlwp = remote->br_lwp;
	rproc = lwptoproc(rlwp);

	/*
	 * Process the ptrace(2) request:
	 */
	switch (ptrace_op) {
	case LX_PTRACE_DETACH:
		error = lx_ptrace_detach(accord, remote, &release_hold);
		break;

	case LX_PTRACE_CONT:
		error = lx_ptrace_cont(remote, LX_PTC_NONE, (int)data);
		break;

	case LX_PTRACE_SYSCALL:
		error = lx_ptrace_cont(remote, LX_PTC_SYSCALL, (int)data);
		break;

#if 0
	case LX_PTRACE_SINGLESTEP:
		error = lx_ptrace_cont(remote, LX_PTC_SINGLESTEP, (int)data);
		break;
#endif

	case LX_PTRACE_SETOPTIONS:
		error = lx_ptrace_setoptions(remote, data);
		break;

	case LX_PTRACE_GETEVENTMSG:
		error = lx_ptrace_geteventmsg(remote, (void *)data);
		break;

	default:
		error = EINVAL;
	}

	/*
	 * Drop the lock on both the tracee process and the tracee list.
	 */
	mutex_exit(&rproc->p_lock);
	mutex_exit(&accord->lxpa_tracees_lock);

	if (release_hold) {
		/*
		 * Release a hold from the accord.
		 */
		lx_ptrace_accord_enter(accord);
		lx_ptrace_accord_rele(accord);
		lx_ptrace_accord_exit(accord);
	}

	return (error);
}

void
lx_ptrace_init(void)
{
	cv_init(&lx_ptrace_busy_cv, NULL, CV_DEFAULT, NULL);

	lx_ptrace_accord_cache = kmem_cache_create("lx_ptrace_accord",
	    sizeof (lx_ptrace_accord_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

void
lx_ptrace_fini(void)
{
	cv_destroy(&lx_ptrace_busy_cv);

	kmem_cache_destroy(lx_ptrace_accord_cache);
}
