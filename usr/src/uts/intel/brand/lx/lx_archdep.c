
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/privregs.h>
#include <sys/pcb.h>
#include <sys/archsystm.h>
#include <sys/stack.h>
#include <sys/sdt.h>

/*
 * Clear out registers and repoint the stack and program counter.  This
 * function is used by the B_JUMP_TO_LINUX brand system call to trampoline into
 * a Linux entrypoint.
 */
void
lx_runexe(klwp_t *lwp, uintptr_t sp, uintptr_t entry, uintptr_t gs)
{
	struct regs *rp = lwptoregs(lwp);

	rp->r_fp = 0;
	rp->r_sp = sp;
	rp->r_pc = entry;

#if defined(__amd64)
	/*
	 * Clear the general registers:
	 */
	rp->r_rax = 0;
	rp->r_rbx = 0;
	rp->r_rcx = 0;
	rp->r_rdx = 0;
	rp->r_rsi = 0;
	rp->r_rdi = 0;

	/*
	 * Set %gs for 32-bit processes if one is provided:
	 */
	if (get_udatamodel() != DATAMODEL_NATIVE && gs != 0) {
		struct pcb *pcb = &lwp->lwp_pcb;

		kpreempt_disable();

		pcb->pcb_gs = 0xffff & gs;

		/*
		 * Ensure we go out via update_sregs
		 */
		pcb->pcb_rupdate = 1;

		kpreempt_enable();
	}
#elif defined(__i386)
	/*
	 * Clear the general registers:
	 */
	rp->r_eax = 0;
	rp->r_ebx = 0;
	rp->r_ecx = 0;
	rp->r_edx = 0;
	rp->r_esi = 0;
	rp->r_edi = 0;

	/*
	 * Set %gs if one is provided:
	 */
	if (gs != 0) {
		rp->r_gs = gs;
	}
#else
#error "unknown x86"
#endif
}

/*
 * The usermode emulation code is illumos library code.  This routine ensures
 * the segment registers are set up correctly for native illumos code.  It
 * should be called _after_ we have stored the outgoing Linux machine state but
 * _before_ we return from the kernel to any illumos native code; e.g. the
 * usermode emulation library, or any interposed signal handlers.
 *
 * See the comment on lwp_segregs_save() for how we handle the usermode
 * registers when we come into the kernel and see update_sregs() for how we
 * restore.
 */
void
lx_switch_to_native(klwp_t *lwp)
{
#if defined(__amd64)
	/*
	 * For 32-bit processes, we ensure that the correct %gs value is
	 * loaded:
	 */
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct pcb *pcb = &lwp->lwp_pcb;

		kpreempt_disable();
		if (pcb->pcb_rupdate == 1) {
			/*
			 * If we are already flushing the segment registers,
			 * then ensure we are flushing the native %gs.
			 */
			pcb->pcb_gs = LWPGS_SEL;
		} else {
			struct regs *rp = lwptoregs(lwp);

			/*
			 * If we are not flushing the segment registers yet,
			 * only do so if %gs is not correct already:
			 */
			if (rp->r_gs != LWPGS_SEL) {
				pcb->pcb_gs = LWPGS_SEL;

				/*
				 * Ensure we go out via update_sregs.
				 */
				pcb->pcb_rupdate = 1;
			}
		}
		kpreempt_enable();
	}
	else if (get_udatamodel() == DATAMODEL_LP64) {
		lx_lwp_data_t *lwpd = lwptolxlwp(lwp);

		if (lwpd->br_ntv_fsbase != 0) {
			struct pcb *pcb = &lwp->lwp_pcb;

			kpreempt_disable();
			if (pcb->pcb_fsbase != lwpd->br_ntv_fsbase) {
				pcb->pcb_fsbase = lwpd->br_ntv_fsbase;

				/*
				 * Ensure we go out via update_sregs.
				 */
				pcb->pcb_rupdate = 1;
			}
			kpreempt_enable();
		}
	}
#elif defined(__i386)
	struct regs *rp = lwptoregs(lwp);

	rp->r_gs = LWPGS_SEL;
#else
#error "unknown x86"
#endif
}

#if defined(__amd64)
/*
 * Call frame for the 64-bit usermode emulation handler:
 *    lx_emulate(ucontext_t *ucp, int syscall_num, uintptr_t *args)
 *
 * old sp: --------------------------------------------------------------
 *  |      - ucontext_t              (register state for emulation)
 *  |      - uintptr_t[6]            (system call arguments array)
 *  |      --------------------------------------------------------------
 * new sp: - bogus return address
 *
 * Arguments are passed in registers, per the AMD64 ABI: %rdi, %rsi and %rdx.
 */
void
lx_emulate_user(klwp_t *lwp, int syscall_num, uintptr_t *args)
{
	proc_t *p = ttoproc(curthread);
	label_t lab;
	volatile uintptr_t top;
	uintptr_t sp;
	uintptr_t uc_addr;
	uintptr_t args_addr;
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	struct regs *rp = lwptoregs(lwp);
	size_t frsz;

	/*
	 * We should not be able to get here unless we have jumped
	 * to Linux code.  XXX Certainly the br_ntv_syscall is invariant,
	 * but it might be possible to affect a different stack_mode...
	 */
	VERIFY(lwpd->br_stack_mode == LX_STACK_MODE_BRAND);

	/*
	 * The AMD64 ABI requires us to align the return address on the stack
	 * so that when the called function pushes %rbp, the stack is 16-byte
	 * aligned.
	 *
	 * This routine, like the amd64 version of sendsig(), depends on
	 * STACK_ALIGN being 16 and STACK_ENTRY_ALIGN being 8.
	 */
#if STACK_ALIGN != 16 || STACK_ENTRY_ALIGN != 8
#error "lx_emulate_user() amd64 did not find the expected stack alignments"
#endif

	/*
	 * We begin at the current native stack pointer, and reserve space for
	 * the ucontext_t we are copying onto the stack, as well as the call
	 * arguments for the usermode emulation handler.
	 *
	 * We 16-byte align the entire frame, and then unalign it again by
	 * adding space for the return address.
	 */
	frsz = SA(sizeof (ucontext_t)) + SA(6 * sizeof (uintptr_t)) +
	    sizeof (uintptr_t);
	VERIFY((frsz & (STACK_ALIGN - 1UL)) == 8);
	VERIFY((frsz & (STACK_ENTRY_ALIGN - 1UL)) == 0);

	if (lwpd->br_ntv_stack == lwpd->br_ntv_stack_current) {
		/*
		 * Nobody else is using the stack right now, so start at the
		 * top.
		 */
		top = lwpd->br_ntv_stack_current;
	} else {
		/*
		 * Drop below the 128-byte reserved region of the stack frame
		 * we are interrupting.
		 */
		top = lwpd->br_ntv_stack_current - STACK_RESERVE;
	}
	top = top & ~(STACK_ALIGN - 1);
	sp = top - frsz;

	uc_addr = top - SA(sizeof (ucontext32_t));
	args_addr = uc_addr - SA(6 * sizeof (uint32_t));

	/*
	 * XXX call to watch_disable_addr() here ?
	 */

	if (on_fault(&lab))
		goto badstack;

	/*
	 * Save the register state we preserved on the way into this brand
	 * system call and drop it on the native stack.
	 */
	{
		/*
		 * Note: the amd64 ucontext_t is 864 bytes.
		 */
		ucontext_t uc;

		/*
		 * XXX is this the correct signal mask to use?
		 */
		savecontext(&uc, &curthread->t_hold);

		/*
		 * Mark this as a system call emulation context:
		 */
		uc.uc_brand_data[0] = (void *)((uintptr_t)uc.uc_brand_data[0] |
		    LX_UC_FRAME_IS_SYSCALL);

		copyout_noerr(&uc, (void *)(uintptr_t)uc_addr, sizeof (uc));
	}

	DTRACE_PROBE3(oldcontext__set, klwp_t *, lwp,
	    uintptr_t, lwp->lwp_oldcontext, uintptr_t, uc_addr);
	lwp->lwp_oldcontext = (uintptr_t)uc_addr;

	/*
	 * Copy the system call arguments out to userland:
	 */
	copyout_noerr(args, (void *)(uintptr_t)args_addr,
	    6 * sizeof (uintptr_t));

	/*
	 * Drop the bogus return address on the stack.
	 */
	suword64_noerr((void *)sp, 0);

	no_fault();

	/*
	 * Pass the arguments to lx_emulate() in the appropriate registers.
	 */
	rp->r_rdi = uc_addr;
	rp->r_rsi = syscall_num;
	rp->r_rdx = args_addr;

	/*
	 * Set stack pointer and return address to the usermode emulation
	 * handler:
	 */
	lwpd->br_stack_mode = LX_STACK_MODE_NATIVE;
	lx_lwp_set_native_stack_current(lwpd, sp);

	/*
	 * Divert execution, on our return, to the usermode emulation stack and
	 * handler:
	 */
	rp->r_fp = 0;
	rp->r_sp = sp;
	rp->r_pc = ptolxproc(p)->l_handler;

	/*
	 * Fix up segment registers, etc.
	 */
	lx_switch_to_native(lwp);

	/*
	 * XXX call to watch_enable_addr() here?
	 */

	return;

badstack:
	no_fault();
	/*
	 * XXX call to watch_enable_addr() here?
	 */

	printf("lx_emulate_user: bad stack (pid %d)!\n",
	    p->p_pid);

	/*
	 * XXX
	 */
	exit(CLD_KILLED, SIGSEGV);
}

#if defined(_SYSCALL32_IMPL)
/*
 * Call frame for the 32-bit usermode emulation handler:
 *    lx_emulate(ucontext_t *ucp, int syscall_num, uintptr_t *args)
 *
 * old sp: --------------------------------------------------------------
 *  |      - ucontext_t              (register state for emulation)
 *  |      - uintptr_t[6]            (system call arguments array)
 *  |      --------------------------------------------------------------
 *  |      - arg2: uintptr_t *       (pointer to arguments array above)
 *  |      - arg1: int               (system call number)
 *  V      - arg0: ucontext_t *      (pointer to context above)
 * new sp: - bogus return address
 */
struct lx_emu_frame32 {
	caddr32_t	retaddr;	/* 0 */
	caddr32_t	ucontextp;	/* 4 */
	int32_t		syscall_num;	/* 8 */
	caddr32_t	argsp;		/* c */
};

/*
 * This function arranges for the lwp to execute the usermode emulation handler
 * for this system call.  The mechanism is similar to signal handling, and this
 * function is modelled on sendsig32().
 */
void
lx_emulate_user32(klwp_t *lwp, int syscall_num, uintptr_t *args)
{
	proc_t *p = ttoproc(curthread);
	label_t lab;
	caddr32_t top;
	caddr32_t sp;
	caddr32_t uc_addr;
	caddr32_t args_addr;
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	struct regs *rp = lwptoregs(lwp);
	size_t frsz;

	/*
	 * We should not be able to get here unless we have jumped
	 * to Linux code.  XXX Certainly the br_ntv_syscall is invariant,
	 * but it might be possible to affect a different stack_mode...
	 */
	VERIFY(lwpd->br_stack_mode == LX_STACK_MODE_BRAND);

	/*
	 * We begin at the current native stack pointer, and reserve space for
	 * the ucontext_t we are copying onto the stack, as well as the call
	 * arguments for the usermode emulation handler.
	 */
	frsz = SA32(sizeof (ucontext32_t)) + SA32(6 * sizeof (uint32_t)) +
	    SA32(sizeof (struct lx_emu_frame32));
	VERIFY((frsz & (STACK_ALIGN32 - 1)) == 0);

	top = (caddr32_t)(lwpd->br_ntv_stack_current & ~(STACK_ALIGN32 - 1));
	sp = top - frsz;

	uc_addr = top - SA32(sizeof (ucontext32_t));
	args_addr = uc_addr - SA32(6 * sizeof (uint32_t));

	/*
	 * XXX call to watch_disable_addr() here ?
	 */

	if (on_fault(&lab))
		goto badstack;

	/*
	 * Save the register state we preserved on the way into this brand
	 * system call and drop it on the native stack.
	 */
	{
		/*
		 * Note: ucontext32_t is 512 bytes.
		 */
		ucontext32_t uc;

		/*
		 * XXX is this the correct signal mask to use?
		 */
		savecontext32(&uc, &curthread->t_hold);
		/*
		 * Mark this as a system call emulation context:
		 */
		uc.uc_brand_data[0] |= LX_UC_FRAME_IS_SYSCALL;
		copyout_noerr(&uc, (void *)(uintptr_t)uc_addr, sizeof (uc));
	}

	DTRACE_PROBE3(oldcontext__set, klwp_t *, lwp,
	    uintptr_t, lwp->lwp_oldcontext, uintptr_t, uc_addr);
	lwp->lwp_oldcontext = (uintptr_t)uc_addr;

	/*
	 * Copy the system call arguments out to userland:
	 */
	{
		uint32_t args32[6];

		args32[0] = args[0];
		args32[1] = args[1];
		args32[2] = args[2];
		args32[3] = args[3];
		args32[4] = args[4];
		args32[5] = args[5];

		copyout_noerr(&args32, (void *)(uintptr_t)args_addr,
		    sizeof (args32));
	}

	/*
	 * Assemble the call frame on the stack.
	 */
	{
		struct lx_emu_frame32 frm;

		frm.retaddr = 0;
		frm.ucontextp = uc_addr;
		frm.argsp = args_addr;
		frm.syscall_num = syscall_num;

		copyout_noerr(&frm, (void *)(uintptr_t)sp, sizeof (frm));
	}

	no_fault();


	/*
	 * Set stack pointer and return address to the usermode emulation
	 * handler:
	 */
	lwpd->br_stack_mode = LX_STACK_MODE_NATIVE;
	lx_lwp_set_native_stack_current(lwpd, sp);

	/*
	 * Divert execution, on our return, to the usermode emulation stack and
	 * handler:
	 */
	rp->r_fp = 0;
	rp->r_sp = sp;
	rp->r_pc = ptolxproc(p)->l_handler;

	/*
	 * Fix up segment registers, etc.
	 */
	lx_switch_to_native(lwp);

	/*
	 * XXX call to watch_enable_addr() here?
	 */

	return;

badstack:
	no_fault();
	/*
	 * XXX call to watch_enable_addr() here?
	 */

	printf("lx_emulate_user32: bad stack (pid %d)!\n",
	    p->p_pid);

	/*
	 * XXX
	 */
	exit(CLD_KILLED, SIGSEGV);
}
#endif	/* _SYSCALL32_IMPL */

#else	/* !__amd64 (__i386) */

void
lx_emulate_user(klwp_t *lwp, int syscall_num, uintptr_t *args)
{
	printf("lx_emulate_user: implement for 32-bit kernel!\n");
	exit(CLD_KILLED, SIGBUS);
}

#endif	/* __amd64 */
