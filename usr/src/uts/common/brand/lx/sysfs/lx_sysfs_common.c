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
 * LX brand "sysfs" emulation: Common Routines.
 */

#include <sys/types.h>
#include <sys/kmem.h>

#include "lx_sysfs.h"


static kmem_cache_t *lx_sysfs_node_cache;

static int lx_sysfs_node_ctor(void *, void *, int);
static void lx_sysfs_node_dtor(void *, void *);


void
lx_sysfs_common_init(void)
{
	lx_sysfs_node_cache = kmem_cache_create("lx_sysfs_node_cache",
	    sizeof (lx_sysfs_node_t), 0, lx_sysfs_node_ctor,
	    lx_sysfs_node_dtor, NULL, NULL, NULL, 0);
}

void
lx_sysfs_common_fini(void)
{
	kmem_cache_destroy(lx_sysfs_node_cache);
}

static int
lx_sysfs_node_ctor(void *buf, void *un, int kmflags)
{
	lx_sysfs_node_t *lxsn = buf;
	vnode_t *vp;

	/*
	 * Allocate the vnode_t for this sysfs node:
	 */
	if ((vp = lxsn->lxsn_vnode = vn_alloc(kmflags)) == NULL) {
		return (-1);
	}

	lxsn->lxsn_type = LX_SYSFS_NT_INVALID;
	lxsn->lxsn_parent = NULL;

	(void) vn_setops(vp, lx_sysfs_vnodeops);
	vp->v_data = lxsn;

	return (0);
}

static void
lx_sysfs_node_dtor(void *buf, void *un)
{
	lx_sysfs_node_t *lxsn = buf;

	/*
	 * Verify object cache invariants:
	 */
	VERIFY(lxsn->lxsn_type == LX_SYSFS_NT_INVALID);
	VERIFY(lxsn->lxsn_parent == NULL);

	vn_free(lxsn->lxsn_vnode);
	lxsn->lxsn_vnode = NULL;
}

lx_sysfs_node_t *
lx_sysfs_node_alloc(vnode_t *dirvp, lx_sysfs_nodetype_t type)
{
	lx_sysfs_node_t *lxsn;
	vnode_t *vp;

	VERIFY(type > LX_SYSFS_NT_INVALID && type < LX_SYSFS_NT_MAXTYPEID);

	lxsn = kmem_cache_alloc(lx_sysfs_node_cache, KM_SLEEP);

	lxsn->lxsn_type = type;
	VN_HOLD(dirvp);
	lxsn->lxsn_parent = dirvp;

	/*
	 * Initialise the vnode.
	 */
	VERIFY((vp = lxsn->lxsn_vnode) != NULL);
	vn_reinit(vp);
	vp->v_flag = VNOCACHE | VNOMAP | VNOSWAP | VNOMOUNT;
	vp->v_vfsp = dirvp->v_vfsp;

	switch (type) {
	case LX_SYSFS_NT_ROOT:
		vp->v_flag |= VROOT;
		vp->v_type = VDIR;
		break;

	default:
		VERIFY(0);
	}

	return (lxsn);
}

void
lx_sysfs_node_free(lx_sysfs_node_t *lxsn)
{
	VERIFY(lxsn != NULL);
	VERIFY(lxsn->lxsn_vnode != NULL);

	/*
	 * Release hold on parent vnode:
	 */
	if (lxsn->lxsn_parent != NULL) {
		VN_RELE(lxsn->lxsn_parent);
		lxsn->lxsn_parent = NULL;
	}

	lxsn->lxsn_type = LX_SYSFS_NT_INVALID;

	kmem_cache_free(lx_sysfs_node_cache, lxsn);
}
