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
 * LX brand "sysfs" emulation: Vnode Operations.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/gfs.h>
#include <lx_proc.h>

#include "lx_sysfs.h"


vnodeops_t *lx_sysfs_vnodeops;


static int
lx_sysfs_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	if (flag & FWRITE) {
		return (EROFS);
	}

	return (0);
}

static int
lx_sysfs_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ct)
{
	return (0);
}

static int
lx_sysfs_read(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	lxpr_uiobuf_t *uiobuf = lxpr_uiobuf_new(uiop);
	int error;

	/*
	 * We presently only support directories.
	 */
	lxpr_uiobuf_seterr(uiobuf, EISDIR);

	error = lxpr_uiobuf_flush(uiobuf);
	lxpr_uiobuf_free(uiobuf);

	return (error);
}

static int
lx_sysfs_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	lx_sysfs_node_t *lxsn = (lx_sysfs_node_t *)vp->v_data;
	lx_kobject_t *lxko = lxsn->lxsn_kobject;

	bzero(vap, sizeof (*vap));
	vap->va_type = vp->v_type;

	vap->va_mode = 0555;
	vap->va_uid = 0;
	vap->va_gid = 0;

	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_nodeid = lx_sysfs_inode(lxko);

	vap->va_nlink = 2 + lxko->lxko_nchildren;
	vap->va_size = vap->va_nlink;

	vap->va_atime = lxsn->lxsn_time;
	vap->va_mtime = lxsn->lxsn_time;
	vap->va_ctime = lxsn->lxsn_time;

	vap->va_blksize = DEV_BSIZE;
	vap->va_nblocks = btod(vap->va_size);

	return (0);
}

static int
lx_sysfs_access(vnode_t *vp, int mode, int flags, cred_t *cr,
    caller_context_t *ct)
{
	if (mode & VWRITE) {
		return (EROFS);
	}

	/*
	 * The superuser always has access:
	 */
	if (secpolicy_proc_access(cr) == 0) {
		return (0);
	}

	return (0);
}

static int
lx_sysfs_lookup(vnode_t *dirvp, char *comp, vnode_t **vpp, pathname_t *pathp,
    int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
    int *direntflags, pathname_t *realpnp)
{
	lx_kobject_t *lxko;
	lx_sysfs_node_t *lxsn = (lx_sysfs_node_t *)dirvp->v_data;
	zone_t *z = lxsn->lxsn_mount->lxsys_zone;
	VERIFY(dirvp->v_type == VDIR);

	if (strcmp(comp, "..") == 0) {
		VN_HOLD(lxsn->lxsn_parent);
		*vpp = lxsn->lxsn_parent;
		return (0);
	}

	if (*comp == '\0' || strcmp(comp, ".") == 0) {
		VN_HOLD(dirvp);
		*vpp = dirvp;
		return (0);
	}

	if ((lxko = lx_kobject_lookup(z, lxsn->lxsn_kobject, comp)) != NULL) {
		lx_sysfs_node_t *clxsn = lx_sysfs_node_alloc(lxsn->lxsn_mount,
		    dirvp, B_FALSE, lxko);

		VN_HOLD(clxsn->lxsn_vnode);
		*vpp = clxsn->lxsn_vnode;
		return (0);
	}

	*vpp = NULL;
	return (ENOENT);
}

static int
lx_sysfs_readdir(vnode_t *dirvp, uio_t *uiop, cred_t *cr, int *eofp,
    caller_context_t *ct, int flags)
{
	lx_sysfs_node_t *lxsn = (lx_sysfs_node_t *)dirvp->v_data;
	zone_t *z = lxsn->lxsn_mount->lxsys_zone;
	lx_kobject_t *lxko = lxsn->lxsn_kobject;
	int error, eof = 0;
	ino64_t pino, ino;
	gfs_readdir_state_t grst;
	offset_t diridx;

	VERIFY(dirvp->v_type == VDIR);

	/*
	 * Get inode numbers for this directory and its parent.
	 */
	if ((error = gfs_get_parent_ino(dirvp, cr, ct, &pino, &ino)) != 0) {
		return (error);
	}

	/*
	 * Initialise generic filesystem readdir data:
	 */
	if ((error = gfs_readdir_init(&grst, 256, 1, uiop, pino, ino,
	    flags)) != 0) {
		return (error);
	}

	while ((error = gfs_readdir_pred(&grst, uiop, &diridx)) == 0) {
		lx_kobject_t *ch;

		if ((ch = lx_kobject_lookup_index(z, lxko, diridx)) == NULL) {
			eof = 1;
		} else {
			error = gfs_readdir_emit(&grst, uiop, diridx,
			    lx_sysfs_inode(ch), ch->lxko_name, 0);
		}

		if (error != 0 || eof != 0) {
			break;
		}
	}

	return (gfs_readdir_fini(&grst, error, eofp, eof));
}

static int
lx_sysfs_readlink(vnode_t *vp, uio_t *uiop, cred_t *cr, caller_context_t *ct)
{
	return (EINVAL);
}

static int
lx_sysfs_sync(void)
{
	return (0);
}

static void
lx_sysfs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	lx_sysfs_node_t *lxsn = (lx_sysfs_node_t *)vp->v_data;

	lx_sysfs_node_free(lxsn);
}

static int
lx_sysfs_cmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{
	if (vn_matchops(vp1, lx_sysfs_vnodeops) ||
	    vn_matchops(vp2, lx_sysfs_vnodeops)) {
		return (vp1 == vp2);
	}

	return (VOP_CMP(vp1, vp2, ct));
}

static int
lx_sysfs_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	*vpp = vp;
	return (0);
}

const fs_operation_def_t lx_sysfs_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = lx_sysfs_open },
	VOPNAME_CLOSE,		{ .vop_close = lx_sysfs_close },
	VOPNAME_READ,		{ .vop_read = lx_sysfs_read },
	VOPNAME_GETATTR,	{ .vop_getattr = lx_sysfs_getattr },
	VOPNAME_ACCESS,		{ .vop_access = lx_sysfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = lx_sysfs_lookup },
	VOPNAME_READDIR,	{ .vop_readdir = lx_sysfs_readdir },
	VOPNAME_READLINK,	{ .vop_readlink = lx_sysfs_readlink },
	VOPNAME_FSYNC,		{ .error = lx_sysfs_sync },
	VOPNAME_SEEK,		{ .error = lx_sysfs_sync },
	VOPNAME_INACTIVE,	{ .vop_inactive = lx_sysfs_inactive },
	VOPNAME_CMP,		{ .vop_cmp = lx_sysfs_cmp },
	VOPNAME_REALVP,		{ .vop_realvp = lx_sysfs_realvp },
	NULL,			NULL
};
