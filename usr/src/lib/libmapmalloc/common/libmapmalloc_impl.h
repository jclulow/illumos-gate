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
 * Copyright (c) 2014, Joyent, Inc.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_LIBMAPMALLOC_IMPL_H
#define	_LIBMAPMALLOC_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum mapmalloc_block_status {
	MMBS_FREE = 0,
	MMBS_BUSY = 1
} mapmalloc_block_status_t;

typedef struct mapmalloc_block {
	uint64_t mmb_magic;	/* magic for heap corruption detection */
	size_t mmb_size;	/* Space available for user */
	struct mapmalloc_page *mmb_page;
	mapmalloc_block_status_t mmb_status;
	struct mapmalloc_block *mmb_next;
	void *mmb_pc;		/* DEBUG: value of pc at malloc() call site */
	void *mmb_memstart[1];
} mapmalloc_block_t;

typedef struct mapmalloc_page {
	size_t mmp_size;	/* Total page size (incl. header) */
	struct mapmalloc_page *mmp_next;
	struct mapmalloc_block mmp_block[1];
} mapmalloc_page_t;

#define	HDR_BLOCK	(sizeof (mapmalloc_block_t) - sizeof (void *))
#define	HDR_PAGE	(sizeof (mapmalloc_page_t) - sizeof (void *))
#define	MINSZ		(sizeof (double))

#define	MAPMALLOC_MAGIC	0xfeedfacefeedfaceULL

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBMAPMALLOC_IMPL_H */
