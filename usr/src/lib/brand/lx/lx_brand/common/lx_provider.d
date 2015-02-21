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

provider lx {
	probe debug(char *buf);
	probe sigdeliver(int sig, void *lx_sigaction, void *lx_sigstack);
	probe sigreturn(void *lx_ucontext, void *ucontext, uintptr_t sp);

	probe signal_delivery_frame_create(void *lx_sigdeliver_frame);
	probe signal_delivery_frame_found(void *lx_sigdeliver_frame);
	probe signal_delivery_frame_corrupt(void *lx_sigdeliver_frame);

	probe signal_post_handler(uintptr_t old_sp, uintptr_t new_sp);

	probe signal_altstack_enable(uintptr_t alt_sp);
	probe signal_altstack_disable();

	probe emulate_enter(void *ucp, int syscall_num, uintptr_t *args);
	probe emulate_return(void *ucp, int syscall_num, uintptr_t ret,
	    uintptr_t errn);
};

#pragma D attributes Evolving/Evolving/ISA provider lx provider
#pragma D attributes Private/Private/Unknown provider lx module
#pragma D attributes Private/Private/Unknown provider lx function
#pragma D attributes Private/Private/ISA provider lx name
#pragma D attributes Private/Private/ISA provider lx args
