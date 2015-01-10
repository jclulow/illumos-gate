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

#include <sys/asm_linkage.h>

#if defined(lint)

void *
caller(void)
{
	return (NULL);
}

#else	/* lint */

#if defined(__amd64)

	ENTRY(caller)
	movq	8(%rbp), %rax
	ret
	SET_SIZE(caller)

#else	/* __i386 */

	ENTRY(caller)
	movl	4(%ebp), %eax
	ret
	SET_SIZE(caller)

#endif

#endif	/* lint */
