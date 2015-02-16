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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Simplified version of malloc(), free() and realloc(), to be linked with
 * utilities that use [s]brk() and do not define their own version of the
 * routines.
 *
 * The algorithm used to get extra memory space by mmap'ing /dev/zero. This
 * breaks if the application closes the open descriptor, so now it uses
 * mmap's MAP_ANON feature.
 *
 * Each call to mmap() creates a page. The pages are linked in a list.
 * Each page is divided in blocks. There is at least one block in a page.
 * New memory chunks are allocated on a first-fit basis.
 * Freed blocks are joined in larger blocks. Free pages are unmapped.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <thread.h>
#include <pthread.h>
#include <synch.h>
#include <string.h>

#include "libmapmalloc_impl.h"

/*
 * Unfortunately, assert() appears to allocate memory with malloc(3C).
 * If we trip an assert, the arena is likely corrupt and _that_ allocation
 * will trip an assert as well.  Instead, an assertion macro with no
 * dependencies is included here.
 */
char *mapmalloc_panicstr;
mapmalloc_block_t *mapmalloc_panicblock;
#define	VERIFY(block, rst)					\
	do {							\
		if (!(rst)) {					\
			mapmalloc_panicblock = (block);		\
			mapmalloc_panicstr = #rst;		\
			abort();				\
		}						\
	} while (0)

#define	VERIFY_MAGIC(block) \
	VERIFY(block, (block)->mmb_magic == MAPMALLOC_MAGIC)
#define	VERIFY_BUSY(block) \
	VERIFY(block, (block)->mmb_status == MMBS_BUSY)
#define	VERIFY_FREE(block) \
	VERIFY(block, (block)->mmb_status == MMBS_FREE)

static mutex_t mapmalloc_lock = DEFAULTMUTEX;

mapmalloc_page_t *mapmalloc_memstart;
static int pagesize;
static void defrag(mapmalloc_page_t *);
static void split(mapmalloc_block_t *,  size_t);
static void *malloc_unlocked(size_t, void *);
static size_t align(size_t, int);

extern void *caller(void);
extern __thread void *mapmalloc_calloc_caller;

void *
malloc(size_t size)
{
	void *our_caller = caller();
	void *retval;

	/*
	 * Our calloc() implementation will store its caller in this
	 * thread-local storage for us to use here.  Without this,
	 * many allocations would have mmb_pc set to calloc().
	 */
	if (mapmalloc_calloc_caller != NULL)
		our_caller = mapmalloc_calloc_caller;

	(void) mutex_lock(&mapmalloc_lock);
	retval = malloc_unlocked(size, our_caller);
	(void) mutex_unlock(&mapmalloc_lock);

	return (retval);
}

static void *
malloc_unlocked(size_t size, void *our_caller)
{
	mapmalloc_block_t *block;
	mapmalloc_page_t *page;

	if (pagesize == 0) {
		pagesize = (int)sysconf(_SC_PAGESIZE);
	}

	size = align(size, MINSZ);

	/*
	 * Try to locate necessary space
	 */
	for (page = mapmalloc_memstart; page != NULL; page =
	    page->mmp_next) {
		for (block = page->mmp_block; block != NULL; block =
		    block->mmb_next) {
			VERIFY_MAGIC(block);

			if (block->mmb_status == MMBS_FREE &&
			    block->mmb_size >= size) {
				goto found;
			}
		}
	}

found:
	/*
	 * Need to allocate a new page
	 */
	if (!page) {
		size_t totsize = size + HDR_PAGE;
		size_t totpage = align(totsize, pagesize);

		if ((page = (mapmalloc_page_t *)mmap(0, totpage,
		    PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1,
		    0)) == MAP_FAILED) {
			return (0);
		}

		page->mmp_next = mapmalloc_memstart;
		mapmalloc_memstart = page;
		page->mmp_size = totpage;
		block = page->mmp_block;
		block->mmb_magic = MAPMALLOC_MAGIC;
		block->mmb_next = 0;
		block->mmb_status = MMBS_FREE;
		block->mmb_size = totpage - HDR_PAGE;
		block->mmb_page = page;
	}

	split(block, size);

	VERIFY_MAGIC(block);
	VERIFY_FREE(block);
	block->mmb_status = MMBS_BUSY;
	block->mmb_pc = our_caller;
	return (&block->mmb_memstart);
}

void *
realloc(void *ptr, size_t size)
{
	void *our_caller = caller();
	mapmalloc_block_t *block;
	size_t osize;
	void *newptr;

	(void) mutex_lock(&mapmalloc_lock);
	if (ptr == NULL) {
		newptr = malloc_unlocked(size, our_caller);
		(void) mutex_unlock(&mapmalloc_lock);
		return (newptr);
	}
	block = (mapmalloc_block_t *)((char *)ptr - HDR_BLOCK);
	VERIFY_MAGIC(block);
	VERIFY_BUSY(block);
	size = align(size, MINSZ);
	osize = block->mmb_size;

	/*
	 * Join block with next one if it is free
	 */
	if (block->mmb_next != NULL && block->mmb_next->mmb_status ==
	    MMBS_FREE) {
		block->mmb_size += block->mmb_next->mmb_size + HDR_BLOCK;
		block->mmb_next = block->mmb_next->mmb_next;
	}

	if (size <= block->mmb_size) {
		split(block, size);
		(void) mutex_unlock(&mapmalloc_lock);
		return (ptr);
	}

	newptr = malloc_unlocked(size, our_caller);
	(void) memcpy(newptr, ptr, osize);
	block->mmb_status = MMBS_FREE;
	defrag(block->mmb_page);
	(void) mutex_unlock(&mapmalloc_lock);
	return (newptr);
}

void
free(void *ptr)
{
	mapmalloc_block_t *block;

	(void) mutex_lock(&mapmalloc_lock);
	if (ptr == NULL) {
		(void) mutex_unlock(&mapmalloc_lock);
		return;
	}

	block = (mapmalloc_block_t *)((char *)ptr - HDR_BLOCK);
	VERIFY_MAGIC(block);

	/*
	 * Check that this is not a double free, then mark the block
	 * freed:
	 */
	VERIFY_BUSY(block);
	block->mmb_status = MMBS_FREE;

	defrag(block->mmb_page);
	(void) mutex_unlock(&mapmalloc_lock);
}

/*
 * Align size on an appropriate boundary
 */
static size_t
align(size_t size, int bound)
{
	if (size < bound) {
		return ((size_t)bound);
	} else {
		return (size + bound - 1 - (size + bound - 1) % bound);
	}
}

static void
split(mapmalloc_block_t *block, size_t size)
{
	VERIFY_MAGIC(block);

	if (block->mmb_size > size + sizeof (mapmalloc_block_t)) {
		mapmalloc_block_t *newblock;
		newblock = (mapmalloc_block_t *)((char *)block + HDR_BLOCK +
		    size);
		newblock->mmb_magic = MAPMALLOC_MAGIC;
		newblock->mmb_next = block->mmb_next;
		block->mmb_next = newblock;
		newblock->mmb_status = MMBS_FREE;
		newblock->mmb_page = block->mmb_page;
		newblock->mmb_size = block->mmb_size - size - HDR_BLOCK;
		block->mmb_size = size;
	}
}

/*
 * Defragmentation
 */
static void
defrag(mapmalloc_page_t *page)
{
	mapmalloc_block_t *block;

	for (block = page->mmp_block; block != NULL; block = block->mmb_next) {
		mapmalloc_block_t *block2;

		VERIFY_MAGIC(block);

		if (block->mmb_status == MMBS_BUSY) {
			continue;
		}
		for (block2 = block->mmb_next; block2 != NULL &&
		    block2->mmb_status == MMBS_FREE;
		    block2 = block2->mmb_next) {
			VERIFY_MAGIC(block2);

			block->mmb_next = block2->mmb_next;
			block->mmb_size += block2->mmb_size + HDR_BLOCK;
		}
	}

	/*
	 * Free page
	 */
	if (page->mmp_block->mmb_size == page->mmp_size - HDR_PAGE) {
		if (page == mapmalloc_memstart) {
			mapmalloc_memstart = page->mmp_next;
		} else {
			mapmalloc_page_t *page2;
			for (page2 = mapmalloc_memstart; page2->mmp_next !=
			    NULL; page2 = page2->mmp_next) {
				if (page2->mmp_next == page) {
					page2->mmp_next = page->mmp_next;
					break;
				}
			}
		}
		(void) munmap((caddr_t)page, page->mmp_size);
	}
}

static void
malloc_prepare()
{
	(void) mutex_lock(&mapmalloc_lock);
}

static void
malloc_release()
{
	(void) mutex_unlock(&mapmalloc_lock);
}

#pragma init(malloc_init)
static void
malloc_init(void)
{
	(void) pthread_atfork(malloc_prepare, malloc_release, malloc_release);
}
