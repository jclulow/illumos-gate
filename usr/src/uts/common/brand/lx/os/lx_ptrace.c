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

/*
 * Emulation of the Linux ptrace(2) interface.
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
 *
 * LOCK ORDERING RULES
 *
 * 1. It is not safe, in general, to hold p_lock (or P_PR_LOCK) for two
 *    different processes at the same time.  This constraint is the primary
 *    reason for the existence (and complexity) of the accord mechanism.
 *
 * 2. In order to facilitate looking up accords by LWP "pid", p_lock for the
 *    tracer process may be held while taking the tracer accord lock
 *    (lxpa_lock).
 *
 * 3. The accord lock (lxpa_lock) should be retained while taking p_lock on a
 *    tracee from the tracee list (lxpa_tracees) to prevent a race with a
 *    concurrent detach or exit.  In keeping with Rule 1, the tracer p_lock
 *    (and P_PR_LOCK) must have been dropped before locking any tracee
 *    processes.
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

/*
 * Flag values for "lxpa_flags" on a ptrace(2) accord.
 */
typedef enum lx_accord_flags {
	LX_ACC_TOMBSTONE = 0x01,
	LX_ACC_CHECK_FOR_EVENTS = 0x02,
} lx_accord_flags_t;

/*
 * This data structure belongs primarily to the tracer, but is reference
 * counted so that it may be freed by whoever references it last.
 */
typedef struct lx_ptrace_accord {
	kmutex_t		lxpa_lock;
	uint_t			lxpa_refcnt;
	lx_lwp_data_t		*lxpa_tracer;
	list_t			lxpa_tracees;

	/*
	 * The sublock protects only the flags and the condition variable.
	 * It is legal to take this lock without holding lxpa_lock.  If
	 * lxpa_lock is held, no process locks may be held before taking
	 * lxpa_sublock.
	 */
	kmutex_t		lxpa_sublock;
	lx_accord_flags_t	lxpa_flags;
	kcondvar_t		*lxpa_cvp;
} lx_ptrace_accord_t;

/*
 */

/*
 * Fetch the accord for this LWP.  If one has not yet been created, and the
 * process is not exiting, allocate it now.  Must be called with p_lock and
 * P_PR_LOCK held for the process containing the target LWP.  The accord lock
 * (lxpa_lock) is held on return.
 */
static int
lx_ptrace_accord_get_locked(klwp_t *lwp, lx_ptrace_accord_t **accord,
    boolean_t allocate_one)
{
	lx_ptrace_accord_t *lxpa;
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	proc_t *p = lwptoproc(lwp);

	/*
	 * The P_PR_LOCK flag serialises the creation and installation of an
	 * accord for a tracer LWP.  This ensures we do not race with any other
	 * tracing frameworks that use the procfs P_PR_LOCK for mutual
	 * exclusion.
	 */
	VERIFY(MUTEX_HELD(p->p_lock));
	VERIFY(p->p_flags & P_PR_LOCK);

	/*
	 * If this LWP does not have an accord, we wish to allocate
	 * and install one.
	 */
	if ((lxpa = lwpd->br_ptrace_accord) == NULL) {
		if (!allocate_one || lwpd->br_ptrace_exiting) {
			/*
			 * Either we do not wish to allocate an accord, or this
			 * LWP has already begun exiting from a ptrace
			 * perspective.
			 */
			*accord = NULL;
			return (ESRCH);
		}

		lxpa = kmem_zalloc(sizeof (*lxpa), KM_SLEEP);

		/*
		 * The initial reference count is 1 because we are referencing
		 * it in from the soon-to-be tracer LWP.
		 */
		lxpa->lxpa_refcnt = 1;
		mutex_init(&lxpa->lxpa_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&lxpa->lxpa_sublock, NULL, MUTEX_DEFAULT, NULL);
		list_create(&lxpa->lxpa_tracees, sizeof (lx_lwp_data_t),
		    offsetof(lx_lwp_data_t, br_ptrace_linkage));
		lxpa->lxpa_cvp = &p->p_cv;

		lxpa->lxpa_tracer = lwpd;
		lwpd->lxpa_ptrace_accord = lxpa;
	}

	/*
	 * Lock the accord for reads before returning it to the caller.
	 */
	mutex_enter(&lxpa->lxpa_lock);

	/*
	 * There should be at least one active reference to this accord,
	 * otherwise it should have been freed.
	 */
	VERIFY(lxpa->lxpa_refcnt > 0);

	*accord = lxpa;
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
lx_ptrace_accord_get_by_pid(pid_t lxpid, lx_ptrace_accord_t **accord)
{
	int ret = ESRCH;
	pid_t apid;
	id_t atid;
	proc_t *aproc;
	klwp_t *alwp;
	lx_lwp_data_t *alwpd;

	VERIFY(MUTEX_NOT_HELD(&curproc->p_lock));

	/*
	 * Locate the process containing the tracer LWP based on its Linux pid
	 * and lock it.
	 */
	if (lx_lpid_to_spair(lxpid, &apid, &atid) != 0 ||
	    (aproc = sprlock(rpid)) == NULL) {
		return (ESRCH);
	}

	if (aproc == curproc) {
		/*
		 * We should not fetch our own accord this way.
		 */
		sprunlock(aproc);
		return (EPERM);
	}

	/*
	 * Locate the tracer LWP itself and ensure that it has not been marked
	 * as exiting.
	 */
	if ((alwp = idtot(aproc, atid)) == NULL ||
	    (alwpd = lwptolxlwp(alwp)) == NULL ||
	    alwpd->br_ptrace_exiting) {
		sprunlock(aproc);
		return (ESRCH);
	}

	/*
	 * Fetch (or allocate) the accord for this LWP:
	 */
	ret = lx_ptrace_accord_get_locked(alwp, accord, B_TRUE);

	/*
	 * Unlock the process and return.
	 */
	sprunlock(aproc);
	return (ret);
}

/*
 * Get (or allocate) the ptrace(2) accord for the current LWP, acting as a
 * tracer.  The caller MUST NOT currently hold either p_lock or P_PR_LOCK on
 * the process containing this LWP.
 *
 * If successful, we return holding the accord lock (lxpa_lock).
 */
static int
lx_ptrace_accord_get(lx_ptrace_accord_t **accord, boolean_t allocate_one)
{
	int ret = ESRCH;
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);

	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	/*
	 * Lock the tracer (this LWP).
	 */
	mutex_enter(&p->p_lock);
	sprlock_proc(p);

	/*
	 * Fetch (or allocate) the accord for this LWP:
	 */
	ret = lx_ptrace_accord_get_locked(lwp, accord, allocate_one);

	sprunlock(p);
	return (ret);
}

/*
 * Drop our reference to this accord and release the mutex.  The caller MUST
 * hold the accord lock (lxpa_lock).  When the routine returns, the accord
 * lock is no longer held and the accord may have been freed.
 */
static void
lx_ptrace_accord_rele(lx_ptrace_accord_t *accord)
{
	VERIFY(MUTEX_HELD(&accord->lxpa_lock));
	VERIFY(accord->lxpa_refcnt > 0);

	if (--accord->lxpa_refcnt == 0) {
		/*
		 * When the reference count drops to zero, we must free
		 * the accord.
		 */
		VERIFY(accord->lxpa_tracer == NULL);
		VERIFY(list_is_empty(&accord->lxpa_tracees));

		mutex_exit(&accord->lxpa_lock);
		mutex_destroy(&accord->lxpa_lock);

		kmem_free(accord);
	} else {
		mutex_exit(&accord->lxpa_lock);
	}
}

/*
 * Place an additional hold on an accord.  The caller MUST hold the accord
 * lock (lxpa_lock).
 */
static void
lx_ptrace_accord_hold(lx_ptrace_accord_t *accord)
{
	VERIFY(MUTEX_HELD(&accord->lxpa_lock));

	accord->lxpa_refcnt++;
}

static void
lx_ptrace_restart_lwp(klwp_t *lwp)
{
	kthread_t *rt = lwptot(lwp);
	proc_t *rproc = lwptoproc(lwp);

	VERIFY(rt != curthread);
	VERIFY(MUTEX_HELD(&rproc->p_lock));
	VERIFY(rproc->p_flags & P_PR_LOCK);

	/*
	 * Check that the LWP is still in "ptrace-stop" and, if so, restart it.
	 */
	thread_lock(rt);
	if (ISTOPPED(rt) && rt->t_whystop == PR_BRANDPRIVATE) {
		rt->t_schedflag |= TS_PSTART;
		rt->t_dtrace_stop = 0;
		setrun_locked(rt);
	}
	thread_unlock(rt);
}

/*
 * For any restarting action (e.g. PTRACE_CONT, PTRACE_SYSCALL or
 * PTRACE_DETACH) to be allowed, the tracee LWP must be in "ptrace-stop".  This
 * check must ONLY be run on tracees of the current LWP.  If the check is
 * successful, we return with the tracee P_PR_LOCK held.
 */
static int
lx_ptrace_lock_if_stopped(lx_ptrace_accord_t *accord, lx_lwp_data_t *remote,
    int *whatp)
{
	klwp_t *rlwp = remote->br_lwp;
	proc_t *rproc = lwptoproc(rlwp);
	kthread_t *rt = lwptot(rlwp);
	boolean_t stopped = B_FALSE;

	/*
	 * We must never check that we, ourselves, are stopped.  We must also
	 * have the accord locked while we lock our tracees.
	 */
	VERIFY(curthread != rt);
	VERIFY(MUTEX_HELD(&accord->lxpa_lock));
	VERIFY(accord->lxpa_tracer == ttolxlwp(curthread));

	/*
	 * Lock the process containing the tracee LWP.
	 */
	mutex_enter(&rproc->p_lock);
#if 0
	/*
	 * XXX do not do this, so that we can take pidlock...
	 */
	sprlock_proc(rproc);
#endif

	/*
	 * We must only check whether tracees of the current LWP are stopped.
	 */
	VERIFY(remote->br_ptrace_tracer == accord);

	if (remote->br_ptrace_exiting) {
		/*
		 * The tracee LWP is currently detaching itself from this
		 * accord as it exits.  It is no longer visible to ptrace(2).
		 */
		mutex_exit(&rproc->p_lock);
#if 0
		sprunlock(rproc);
#endif
		return (ESRCH);
	}

	/*
	 * Lock the thread and check if it is in "ptrace-stop".  We represent
	 * the "ptrace-stop" condition as a thread marked for /proc stop (i.e.
	 * !TS_PSTART) with a stop reason of PR_BRANDPRIVATE.
	 */
	thread_lock(rt);
	if (ISTOPPED(rt) && rt->t_whystop == PR_BRANDPRIVATE) {
		/*
		 * The tracee is in "ptrace-stop", and we may return it locked.
		 */
		stopped = B_TRUE;
		if (whatp != NULL) {
			*whatp = rt->t_whatstop;
		}
	}
	thread_unlock(rt);

	if (!stopped) {
		/*
		 * The tracee is not in "ptrace-stop", so we release the
		 * process.
		 */
		if (whatp != NULL)
			*whatp = 0;
		mutex_exit(&rproc->p_lock);
#if 0
		sprunlock(rproc);
#endif
		return (ESRCH);
	}

	/*
	 * The tracee is stopped.  We return holding its process lock so that
	 * the called may manipulate it.
	 */
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
int
lx_ptrace_detach(pid_t lx_pid)
{
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);
	lx_ptrace_acord_t *accord;
	lx_lwp_data_t *remote;
	boolean_t found = B_FALSE;
	boolean_t release_accord = B_TRUE;
	kthread_t *rt;
	proc_t *rproc;
	int error;

	if (lwpd->br_pid == lx_pid) {
		/*
		 * We cannot untrace ourselves.
		 */
		return (ESRCH);
	}

	/*
	 * Ensure that we have an accord and obtain a lock on it.  This
	 * routine should not fail because the LWP cannot make ptrace(2) system
	 * calls after it has begun exiting.
	 */
	VERIFY(lwpd->br_ptrace_exiting == B_FALSE);
	VERIFY(lx_ptrace_accord_get(&accord, B_TRUE) == 0);

	/*
	 * Does the tracee list contain the pid in question?
	 */
	for (remote = list_head(&accord->lxpa_list); remote != NULL;
	    remote = list_next(&accord->lxpa_list, remote)) {
		if (remote->br_pid == lx_pid) {
			found = B_TRUE;
			break;
		}
	}
	if (!found) {
		/*
		 * The requested pid does not appear in the tracee list.
		 */
		mutex_exit(&accord->lxpa_lock);
		return (ESRCH);
	}

	if ((error = lx_ptrace_lock_if_stopped(accord, remote, NULL)) != 0) {
		/*
		 * The LWP was not in "ptrace-stop".
		 */
		mutex_exit(&accord->lxpa_lock);
		return (error);
	}

	/*
	 * lx_ptrace_lock_if_stopped() will take p_lock, but we also want
	 * P_PR_LOCK.
	 */
	rproc = lwptoproc(remote->br_lwp);
	sprlock_proc(rproc);

	/*
	 * The tracee LWP was in "ptrace-stop" and we now hold its P_PR_LOCK
	 * and p_lock.  Detach the LWP from the accord and set it running.
	 */
	remote->br_ptrace_tracer = NULL;
	remote->br_ptrace_syscall = B_FALSE;
	list_remove(&accord->lxpa_list, remote);
	lx_ptrace_restart_lwp(remote->br_lwp);

	/*
	 * Release the process containing the former tracee LWP.
	 */
	sprunlock(rproc);

	/*
	 * Release the hold this tracee had on the accord.  This will also drop
	 * the accord lock.
	 */
	lx_ptrace_accord_rele(accord);

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

int
lx_ptrace_attach(pid_t lx_pid)
{
	int error = ESRCH;
	/*
	 * Our (Tracer) LWP:
	 */
	lx_ptrace_acord_t *accord;
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);
	/*
	 * Remote (Tracee) LWP:
	 */
	pid_t rpid;
	id_t rtid;
	proc_t *rproc;
	klwp_t *rlwp;
	lx_lwp_data_t *rlwpd;

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
	VERIFY(lwpd->br_ptrace_exiting == B_FALSE);
	VERIFY(lx_ptrace_accord_get(&accord, B_TRUE) == 0);

	/*
	 * Locate the process containing the tracee LWP based on its Linux pid
	 * and lock it.
	 */
	if (lx_lpid_to_spair(lx_pid, &rpid, &rtid) != 0 ||
	    (rproc = sprlock(rpid)) == NULL) {
		/*
		 * We could not find the target process.
		 */
		mutex_exit(&accord->lxpa_lock);
		return (ESRCH);
	}

	/*
	 * Locate the tracee LWP.
	 */
	if ((rlwp = idtot(rproc, rtid)) == NULL ||
	    (rlwpd = lwptolxlwp(rlwp)) == NULL) {
		/*
		 * The LWP could not be found or was not branded.
		 */
		sprunlock(rproc);
		mutex_exit(&accord->lxpa_lock);
		return (ESRCH);
	}

	/*
	 * We now hold the lock on the tracee.  Attempt to install ourselves
	 * as the tracer.
	 */
	if (rlwpd->br_ptrace_exiting) {
		/*
		 * This LWP has already exited from a ptrace(2) point of view.
		 */
		error = ESRCH;
	} else if (rlwpd->br_ptrace_tracer != NULL) {
		/*
		 * This LWP is already being traced.
		 */
		error = EPERM;
	} else {
		/*
		 * Bond the tracee to the accord.
		 */
		lx_ptrace_accord_hold(accord);
		rlwpd->br_ptrace_tracer = accord;
		list_insert_tail(&accord->lxpa_tracees, rlwpd);

		/*
		 * Send a thread-directed SIGLWP and have the usermode emulation bring
		 * that back in as a fake SIGSTOP.
		 */
		sigtoproc(rproc, rthr, SIGLWP);
		error = 0;
	}

	/*
	 * Unlock the process containing the tracee LWP.
	 */
	sprunlock(rproc);
	mutex_exit(&accord->lxpa_lock);
	return (error);
}

int
lx_ptrace_traceme(void)
{
	int error;
	/*
	 * Our (Tracee) LWP:
	 */
	klwp *lwp = ttolwp(curthread);
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
	    NULL))) != 0) {
		/*
		 * Could not determine the Linux pid of the parent LWP, or
		 * could not get the accord for that LWP.
		 */
		return (error);
	}

	mutex_enter(&accord->lxpa_sublock);
	if (accord->lxpa_flags & LX_ACC_TOMBSTONE) {
		/*
		 * The accord is marked for death; give up now.
		 */
		mutex_exit(&accord->lxpa_sublock);
		mutex_exit(&accord->lxpa_lock);
		return (ESRCH);
	}
	mutex_exit(&accord->lxpa_sublock);

	/*
	 * Bump the reference count so that the accord is not freed.  We need
	 * to drop the accord lock before we take our own p_lock.
	 */
	lx_ptrace_accord_hold(accord);
	mutex_exit(&accord->lxpa_lock);

	/*
	 * We now lock _our_ process and determine if we can install our parent
	 * as our tracer.
	 */
	mutex_enter(&p->p_lock);
	sprlock_proc(p);
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
		lwpd->br_ptrace_tracer = accord;
		error = 0;
	}
	sprunlock(p);

	/*
	 * Reacquire the accord lock and add us to the tracee list.  Once we
	 * are in the tracee list, it is the responsibility of the tracer to
	 * detach us.
	 */
	if (error == 0) {
		mutex_enter(&accord->lxpa_lock);
		mutex_enter(&accord->lxpa_sublock);
		if (!(accord->lxpa_flags & LX_ACC_TOMBSTONE)) {
			/*
			 * Put ourselves in the tracee list for this accord
			 * and return success to the caller.
			 */
			list_insert_tail(&accord->lxpa_tracees, lwpd);
			mutex_exit(&accord->lxpa_sublock);
			mutex_exit(&accord->lxpa_lock);
			return (0);
		}
		mutex_exit(&accord->lxpa_sublock);

		/*
		 * The accord has been marked for death.  We must
		 * untrace ourselves.
		 */
		error = ESRCH;
		mutex_exit(&accord->lxpa_lock);
	}

	/*
	 * Our optimism was unjustified: We were unable to attach.  We need to
	 * lock the process containing this LWP again in order to remove the
	 * tracer.
	 */
	VERIFY(error != 0);
	mutex_enter(&p->p_lock);
	sprlock_proc(p);

	/*
	 * Verify that things were as we left them:
	 */
	VERIFY(lwpd->br_ptrace_syscall == B_FALSE);
	VERIFY(lwpd->br_ptrace_tracer == accord);

	lwpd->br_ptrace_tracer = NULL;
	sprunlock(p);

	/*
	 * Remove our speculative hold on the accord, possibly causing it to be
	 * freed in the process.
	 */
	mutex_enter(&accord->lxpa_lock);
	lx_ptrace_accord_rele(accord);

	return (error);
}


void
lx_ptrace_stop(int what)
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
		return;

	/*
	 * Lock this process and re-check the condition.
	 */
	mutex_enter(&p->p_lock);
	if (lwpd->br_ptrace_tracer == NULL) {
		VERIFY(lwpd->br_ptrace_syscall == B_FALSE);
		mutex_exit(&p->p_lock);
		return;
	}

	if (what == LX_PR_SYSENTRY || what == LX_PR_SYSEXIT) {
		/*
		 * This is a syscall-entry-stop or syscall-exit-stop point.
		 */
		if (!lwpd->br_ptrace_syscall) {
			/*
			 * A system call stop has not been requested.
			 */
			mutex_exit(&p->p_lock);
			return;
		}

		/*
		 * The PTRACE_SYSCALL restart command applies only to the next
		 * system call entry or exit.  The tracer must restart us with
		 * PTRACE_SYSCALL while we are in ptrace-stop for us to fire
		 * again at the next system call boundary.
		 */
		lwpd->br_ptrace_syscall = B_FALSE;
	}

	/*
	 * Put the LWP in ptrace-stop.
	 */
	stop(PR_BRANDPRIVATE, what);

	/*
	 * We are back from ptrace-stop.
	 */
	mutex_exit(&p->p_lock);
}

/*
 * This routine is called from lx_exitlwp() when an LWP is ready to exit.  If
 * this LWP is being traced, it will be detached from the tracer's accord.  The
 * routine will also detach any LWPs being traced by this LWP.
 *
 * The routine must be called without holding any process locks.
 */
void
lx_ptrace_exit(void)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	lx_ptrace_accord_t *accord;

	/*
	 * Lock the current process.
	 */
	mutex_enter(&p->p_lock);
	sprlock_proc(p);

	/*
	 * Mark our LWP as exiting from a ptrace perspective.  This will
	 * prevent a new accord from being allocated if one does not exist
	 * already, and will make us invisible to PTRACE_ATTACH/PTRACE_TRACEME.
	 */
	VERIFY(lwpd->br_ptrace_exiting == B_FALSE);
	lwpd->br_ptrace_exiting = B_TRUE;

	/*
	 * Detach us from any LWPs we may be tracing, and the LWP that is
	 * tracing us if one exists.
	 */
	if ((accord = lwpd->br_ptrace_tracer) != NULL) {
		/*
		 * We are traced by another LWP and must detach ourselves.
		 */
		lx_ptrace_exit_tracee(p, lwpd, accord);
	}

	if (lx_ptrace_accord_get_locked(&accord, B_FALSE) == 0) {
		/*
		 * We have been tracing other LWPs, and must detach from
		 * them and clean up our accord.
		 */
		lx_ptrace_exit_tracer(p, lwpd, lwpd->br_ptrace_accord);
	}

	sprunlock(p);
}

static void
lx_ptrace_exit_tracer(proc_t *p, lx_lwp_data_t *lwpd,
    lx_ptrace_accord_t *accord)
{
	int ret;

	VERIFY(MUTEX_HELD(&p->p_lock));
	VERIFY(p->p_flags & P_PR_LOCK);
	VERIFY(lwpd->br_ptrace_exiting == B_TRUE);

	/*
	 * We hold the accord lock.  Drop our process lock so that we may take
	 * the locks of tracees.
	 */
	VERIFY(MUTEX_HELD(&accord->lxpa_lock));
	sprunlock(p);

	/*
	 * Mark this accord for death.  Once we set this flag, we must not
	 * release the accord lock until the tracee list is empty.
	 */
	mutex_enter(&accord->lxpa_sublock);
	VERIFY((accord->lxpa_flags & LX_ACC_TOMBSTONE) == 0);
	accord->lxpa_flags |= LX_ACC_TOMBSTONE;
	accord->lxpa_cvp = NULL;
	mutex_exit(&accord->lxpa_sublock);

	/*
	 * Walk the list of tracees, removing them and setting them runnable if
	 * they are stopped.
	 */
	while (!list_is_empty(&accord->lxpa_tracees)) {
		lx_lwp_data_t *remote = list_head(&accord->lxpa_tracees);
		klwp_t *rlwp = lxlwptolwp(remote);
		proc_t *rproc = lwptoproc(rlwp);

		/*
		 * Lock the process containing this tracee LWP.
		 */
		mutex_enter(&rproc->p_lock);
		sprlock_proc(rproc);

		/*
		 * We now hold p_lock and P_PR_LOCK on the process.  Remove the
		 * tracee from the list.
		 */
		list_remove(&accord->lxpa_tracees, remote);

		/*
		 * Due to the lock ordering rules, the tracee must drop its
		 * process lock before acquiring a lock on the accord by which
		 * it is traced.  By agreement with lx_ptrace_exit_tracee(), if
		 * the tracee has already begun exiting then we do not clear
		 * its tracer pointer or remove its hold on the accord.  The
		 * tracee will do this cleanup after we release the accord.
		 */
		if (!remote->br_ptrace_exiting) {
			remote->br_ptrace_syscall = B_FALSE;
			remote->br_ptrace_tracer = NULL;
			lx_ptrace_accord_rele(accord);
		}

		/*
		 * Ensure that the LWP is not in ptrace-stop.
		 */
		lx_ptrace_restart_lwp(rlwp);

		/*
		 * Unlock the former tracee.
		 */
		sprunlock(rproc);
	}

	/*
	 * Release our hold on the accord.  If we completely detached all
	 * tracee LWPs, this will free the accord.  Otherwise, it will be freed
	 * when they complete their cleanup.
	 */
	lx_ptrace_accord_rele(accord);

	sprlock_proc(p);
	return (0);
}

static void
lx_ptrace_exit_tracee(proc_t *p, lx_lwp_data_t *lwpd,
    lx_ptrace_accord_t *accord)
{
	boolean_t tombstone = B_FALSE;

	VERIFY(MUTEX_HELD(&p->p_lock));
	VERIFY(p->p_flags & P_PR_LOCK);
	VERIFY(lwpd->br_ptrace_exiting == B_TRUE);

	/*
	 * In order to satisfy the lock ordering rules, we must drop our
	 * process locks before locking the accord to which we are subservient.
	 */
	sprunlock(p);

	/*
	 * Once we own the accord lock, we re-lock our process.  After that, we
	 * may take the accord sublock to check flags.
	 */
	mutex_enter(&accord->lxpa_lock);
	mutex_enter(&p->p_lock);
	sprlock_proc(p);

	mutex_enter(&accord->lxpa_sublock);
	tombstone = (accord->lxpa_flags & LX_ACC_TOMBSTONE) != 0;
	mutex_exit(&accord->lxpa_sublock);

	VERIFY(lwpd->br_ptrace_tracer == accord);
	lwpd->br_ptrace_tracer = NULL;

	if (tombstone) {
		/*
		 * Our tracer may be able to run lx_ptrace_exit_tracer() before
		 * we are able to acquire the accord lock.  By agreement with
		 * that routine, if we have set "br_ptrace_exiting" it will
		 * remove us from the tracee list, but will not drop the hold
		 * we have on the accord.
		 */
		VERIFY(!list_link_active(&lwpd->br_ptrace_linkage));
	} else {
		/*
		 * The tracer is not exiting.  We must remove ourselves from
		 * the list.
		 */
		VERIFY(list_link_active(&lwpd->br_ptrace_linkage));
		list_remove(&accord->lxpa_tracees, lwpd);
	}

	/*
	 * Release our hold on the accord.
	 */
	lx_ptrace_accord_rele(accord);

	/*
	 * We return holding p_lock and P_PR_LOCK for our process.
	 */
}

/*
 * Called to notify the tracer of an event of interest.  The caller must hold
 * p_lock on the current process.
 */
static void
lx_ptrace_notify(void)
{
	klwp_t *lwp = ttolwp(curthread);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	proc_t *p = lwptoproc(lwp);
	lx_ptrace_accord_t *accord;

	VERIFY(MUTEX_HELD(&p->p_lock));

	if ((accord = lwpd->br_ptrace_tracer) == NULL) {
		/*
		 * No tracer at present.
		 */
		return;
	}

	lwpd->br_ptrace_new_event = B_TRUE;

	/*
	 * We take the accord sublock to check flags and use the condition
	 * variable for the tracer.
	 */
	mutex_enter(&accord->lxpa_sublock);
	if (accord->lxpa_flags & LX_ACC_TOMBSTONE) {
		/*
		 * The accord is marked for death; give up now.
		 */
		mutex_exit(&accord->lxpa_sublock);
		return;
	}

	/*
	 * Tell lx_ptrace_consume() to check for events.
	 */
	accord->lxpa_flags |= LX_ACC_CHECK_FOR_EVENTS;
	mutex_exit(&accord->lxpa_sublock);

	/*
	 * Drop our process lock so that we may take pidlock.
	 */
	mutex_exit(&p->p_lock);

	/*
	 * Take pidlock -- if the tracer LWP is blocked in waitid(), we want to
	 * wake it up in the same manner as sigcld().  The accord points to
	 * p_cv on the "parent" process; i.e. the process containing the tracer
	 * LWP.
	 */
	mutex_enter(&pidlock);
	mutex_enter(&accord->lxpa_sublock);
	if (accord->lxpa_cvp != NULL)
		cv_broadcast(accord->lxpa_cvp);
	mutex_exit(&accord->lxpa_sublock);

	/*
	 * Reacquire p_lock before releasing pidlock.
	 */
	mutex_enter(&p->p_lock);
	mutex_exit(&pidlock);

	/*
	 * We return as we were called: holding p_lock on this process.
	 */
}

/*
 * This hook is called by stop() when the stop reason is PR_BRANDPRIVATE.
 * The current process p_lock is held.
 */
void
lx_stop_notify(int what)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);

	/*
	 * Validate the stop sub-reason:
	 */
	switch (what) {
	case LX_PR_SYSENTRY:
	case LX_PR_SYSEXIT:
	case LX_PR_SIGNALLED:
		lwpd->br_ptrace_stop_reason = what;
		break;
	default:
		cmn_err(CE_PANIC, "invalid lx private stop reason: %d", what);
	}

	lx_ptrace_notify();
}

/*
 * Consume the next available ptrace(2) event queued against the accord for
 * this LWP.  The event will be emitted as if through waitid(), and converted
 * by lx_waitpid() and friends before the return to usermode.
 */
int
lx_waitid_helper(idtype_t idtype, id_t id, k_siginfo_t *ip, int options,
    boolean_t *brand_wants_wait, int *ret)
{
	lx_ptrace_accord_t *accord;
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *local = lwptolxlwp(lwp);
	lx_lwp_data_t *remote;
	boolean_t found = B_FALSE;
	
	VERIFY(MUTEX_HELD(&pidlock));
	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	if (local->br_stack_mode != LX_STACK_MODE_BRAND) {
		/*
		 * If this system call did not originate from Linux code,
		 * we do not want to report ptrace(2) events through waitid()
		 * calls.
		 */
		*brand_wants_wait = B_FALSE;
		return (-1);
	}

	if (lx_ptrace_accord_get(&accord, B_FALSE) != 0) {
		/*
		 * This LWP does not have an accord; it cannot be tracing.
		 */
		*brand_wants_wait = B_FALSE;
		return (-1);
	}

	if (list_is_empty(&accord->lxpa_tracees)) {
		/*
		 * Though it has an accord, there are currently no tracees in
		 * the list for this LWP.
		 */
		mutex_exit(&accord->lxpa_lock);
		*brand_wants_wait = B_FALSE;
		return (-1);
	}

	/*
	 * Walk the list of tracees and determine if any of them have events
	 * to report.  Holding the accord lock prevents any tracees from
	 * being detached or freed while we walk.
	 */
	for (remote = list_head(&accord->lxpa_tracees), remote != NULL;
	    remote = list_next(&accord->lxpa_tracees, remote)) {
		klwp_t *rlwp = remote->br_lwp;
		proc_t *rproc = lwptoproc(rlwp);
		int what = 0;

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
		}

		/*
		 * Check if this LWP is in "ptrace-stop".  If in the correct
		 * stop condition, lock the process containing the tracee LWP.
		 */
		if (lx_ptrace_lock_if_stopped(accord, remote, &what) != 0) {
			continue;
		}

		/*
		 * If the current ptrace-stop has been posted by waitid()
		 * already, we do not want to post it again.
		 */
		if (!remote->br_ptrace_new_event) {
			mutex_exit(&rproc->p_lock);
			continue;
		}

		/*
		 * Populate our k_siginfo_t with data about this "ptrace-stop"
		 * condition:
		 */
		bzero(ip, sizeof (*ip));
		ip->si_signo = SIGCLD;
		ip->si_code = CLD_TRAPPED;
		ip->si_pid = remote->br_pid;

		switch (what) {
		case LX_PR_SYSENTRY:
		case LX_PR_SYSEXIT:
			/*
			 * A "syscall-stop" is reported as WSTOPSIG(status)
			 * giving SIGTRAP.
			 * XXX handle PTRACE_O_TRACESYSGOOD
			 */
			ip->si_status = SIGTRAP;
			break;
		case LX_PR_SIGNALLED:
			break;
		default:
			cmn_err(CE_PANIC, "unexpected brand-private stop: %d",
			    what);
		}

		/*
		 * XXX need to handle (see ptrace(2) on Linux):
		 *  __WCLONE
		 *  __WALL
		 *  __WNOTHREAD
		 */

		/*
		 * If WNOWAIT was specified, do not mark the event as posted
		 * so that it may be re-fetched on another call to waitid().
		 */
		if (!(options & WNOWAIT)) {
			remote->br_ptrace_new_event = B_FALSE;
		}

		sprunlock(rproc);
	}

	/*
	 * There were no events of interest, but we have tracees.  Signal to
	 * waitid() that it should block if the provided flags allow for it.
	 */
	*brand_wants_wait = B_TRUE;
	mutex_exit(&accord->lxpa_lock);
}
