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
#include <sys/brand.h>
#include <sys/lx_brand.h>

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
	VERIFY(lxsn->lxsn_parent == NULL);

	vn_free(lxsn->lxsn_vnode);
	lxsn->lxsn_vnode = NULL;
}

lx_sysfs_node_t *
lx_sysfs_node_alloc(lx_sysfs_mount_t *lxmnt, vnode_t *dirvp,
    boolean_t is_root, lx_kobject_t *lxko)
{
	lx_sysfs_node_t *lxsn;
	vnode_t *vp;

	VERIFY(lxko != NULL);

	lxsn = kmem_cache_alloc(lx_sysfs_node_cache, KM_SLEEP);

	VN_HOLD(dirvp);
	lxsn->lxsn_parent = dirvp;
	gethrestime(&lxsn->lxsn_time);
	lxsn->lxsn_kobject = lxko;
	lxsn->lxsn_mount = lxmnt;

	/*
	 * Initialise the vnode.
	 */
	VERIFY((vp = lxsn->lxsn_vnode) != NULL);
	vn_reinit(vp);
	vp->v_type = VDIR;
	vp->v_flag = VNOCACHE | VNOMAP | VNOSWAP | VNOMOUNT;
	vp->v_vfsp = dirvp->v_vfsp;
	if (is_root) {
		vp->v_flag |= VROOT;
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

	lxsn->lxsn_time = (timestruc_t){ 0 };
	lxsn->lxsn_kobject = NULL;

	kmem_cache_free(lx_sysfs_node_cache, lxsn);
}

ino64_t
lx_sysfs_inode(lx_kobject_t *lxko)
{
	VERIFY(lxko != NULL);

	return ((ino64_t)(lxko->lxko_id + 0x1000));
}
