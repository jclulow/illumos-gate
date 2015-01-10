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
 */
/*
 * Copyright 2015, Joyent, Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

extern void *caller(void);

/*
 * We stash our caller in this thread-local variable such that our malloc()
 * implementation, if used, can use it to populate the mmb_pc member of a
 * mapalloc_block_t.
 */
__thread void *mapmalloc_calloc_caller = NULL;

/*
 * calloc - allocate and clear memory block
 */

void *
calloc(size_t num, size_t size)
{
	void *mp;
	size_t total;

	if (num == 0 || size == 0) {
		total = 0;
	} else {
		total = num * size;

		/* check for overflow */
		if ((total / num) != size) {
			errno = ENOMEM;
			return (NULL);
		}
	}

	mapmalloc_calloc_caller = caller();
	mp = malloc(total);
	mapmalloc_calloc_caller = NULL;
	if (mp == NULL)
		return (NULL);

	(void) memset(mp, 0, total);
	return (mp);
}

/*ARGSUSED*/
void
cfree(void *p, size_t num, size_t size)
{
	free(p);
}
