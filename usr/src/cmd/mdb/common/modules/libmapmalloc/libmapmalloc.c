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
 * libmapmalloc dmod
 */

#include <mdb/mdb_modapi.h>
#include <stddef.h>

#include "libmapmalloc_impl.h"

static int
mdb_mapmalloc_walk_pages_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;
	uintptr_t memstart;

	if (wsp->walk_addr != NULL)
		return (WALK_NEXT);

	/*
	 * This is a global walk, so lookup the "memstart" symbol as
	 * the first `struct page` to walk:
	 */
	if (mdb_lookup_by_name("mapmalloc_memstart", &sym) != 0) {
		mdb_warn("could not find symbol 'memstart'");
		return (WALK_ERR);
	}

	if (mdb_vread(&memstart, sizeof (memstart), sym.st_value) == -1) {
		mdb_warn("could not load 'memstart'");
		return (WALK_ERR);
	}

	wsp->walk_addr = memstart;

	return (WALK_NEXT);
}

static int
mdb_mapmalloc_walk_pages_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	int rv;
	mapmalloc_page_t page;

	addr = wsp->walk_addr;

	/*
	 * Pass this "struct page" address out:
	 */
	if ((rv = wsp->walk_callback(wsp->walk_addr, NULL,
	    wsp->walk_cbdata)) != WALK_NEXT) {
		return (rv);
	}

	/*
	 * Read in the struct, so that we can follow the pointer chain:
	 */
	if (mdb_vread(&page, sizeof (page), addr) == -1) {
		mdb_warn("could not read mapmalloc_page_t (%p)", addr);
		return (WALK_ERR);
	}

	if (page.mmp_next == NULL)
		return (WALK_DONE);
	wsp->walk_addr = (uintptr_t)page.mmp_next;

	return (WALK_NEXT);
}

static int
mdb_mapmalloc_walk_blocks_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("mapmalloc_pages", wsp) == -1) {
		mdb_warn("could not walk 'mapmalloc_pages'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
mdb_mapmalloc_walk_blocks_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	mapmalloc_page_t page;

	/*
	 * Load this "struct page":
	 */
	addr = wsp->walk_addr;
	if (mdb_vread(&page, sizeof (page), addr) == -1) {
		mdb_warn("could not read mapmalloc_page_t (%p)", addr);
		return (WALK_ERR);
	}

	/*
	 * The first block is embedded in this page:
	 */
	addr += offsetof(mapmalloc_page_t, mmp_block);

	/*
	 * Read each "struct block" from this "struct page":
	 */
	for (;;) {
		int rv;
		mapmalloc_block_t block;

		if ((rv = wsp->walk_callback(addr, NULL, wsp->walk_cbdata)) !=
		    WALK_NEXT) {
			return (rv);
		}

		if (mdb_vread(&block, sizeof (block), addr) == -1) {
			mdb_warn("could not read mapmalloc_block_t (%p)", addr);
			return (WALK_ERR);
		}

		if (block.mmb_next == NULL)
			return (WALK_NEXT);

		addr = (uintptr_t)block.mmb_next;
	}
}

static const mdb_walker_t walkers[] = {
	{ "mapmalloc_pages", "walk pages in libmapmalloc page list",
		mdb_mapmalloc_walk_pages_init,
		mdb_mapmalloc_walk_pages_step },
	{ "mapmalloc_blocks", "walk blocks in libmapmalloc page list",
		mdb_mapmalloc_walk_blocks_init,
		mdb_mapmalloc_walk_blocks_step },
	{ NULL, NULL, NULL, NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION,
	NULL,
	walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
