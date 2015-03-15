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
 * LX brand "sysfs" emulation: VFS Operations.
 */

#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/dnlc.h>
#include <sys/mount.h>
#include <sys/policy.h>

#include "lx_sysfs.h"

/*
 * Forward declarations.
 */
static int lx_sysfs_init(int, char *);
static int lx_sysfs_mount(vfs_t *, vnode_t *, struct mounta *, cred_t *);
static int lx_sysfs_unmount(vfs_t *, int, cred_t *);
static int lx_sysfs_root(vfs_t *, vnode_t **);
static int lx_sysfs_statvfs(vfs_t *, statvfs64_t *);

/*
 * Module-level Parameters.
 */
static int lx_sysfs_fstype;
static dev_t lx_sysfs_dev;
static kmutex_t lx_sysfs_mount_lock;

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"lx_sysfs",
	lx_sysfs_init,
	VSW_ZMOUNT,
	NULL
};

/*
 * Kernel module linkage.
 */
extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops,
	"lx brand sysfs",
	&vfw
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlfs,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&modlinkage, mip));
}

int
_fini(void)
{
	int retval;

	if ((retval = mod_remove(&modlinkage)) != 0) {
		goto done;
	}

done:
	return (retval);
}

static int
lx_sysfs_init(int fstype, char *name)
{
	static const fs_operation_def_t lx_sysfs_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = lx_sysfs_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = lx_sysfs_unmount },
		VFSNAME_ROOT,		{ .vfs_root = lx_sysfs_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = lx_sysfs_statvfs },
		NULL,			NULL
	};
	extern const fs_operation_def_t lx_sysfs_vnodeops_template[];
	int error;
	major_t dev;

	VERIFY((lx_sysfs_fstype = fstype) != 0);

	mutex_init(&lx_sysfs_mount_lock, NULL, MUTEX_DEFAULT, NULL);

	if ((error = vfs_setfsops(fstype, lx_sysfs_vfsops_template,
	    NULL)) != 0) {
		cmn_err(CE_WARN, "lx_sysfs_init: bad vfs ops template");
		return (error);
	}

	if ((error = vn_make_ops(name, lx_sysfs_vnodeops_template,
	    &lx_sysfs_vnodeops)) != 0) {
		cmn_err(CE_WARN, "lx_sysfs_init: bad vnode ops template");
		return (error);
	}

	if ((dev = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "lx_sysfs_init: can't get unique device "
		    "number");
		dev = 0;
	}

	lx_sysfs_dev = makedevice(dev, 0);

	return (0);
}

static int
lx_sysfs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	lx_sysfs_mount_t *lxmnt;
	zone_t *zone = curproc->p_zone;

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0) {
		return (EPERM);
	}

	if (mvp->v_type != VDIR) {
		return (ENOTDIR);
	}

	if (zone == global_zone) {
		/*
		 * This filesystem is only useful within an LX-branded zone.
		 * XXX Is this correct, or do we actually need to do what
		 * lxprocfs is doing here?
		 */
		return (EBUSY);
	}

	vfs_setresource(vfsp, "lx_sysfs", 0);

	lxmnt = kmem_zalloc(sizeof (*lxmnt), KM_SLEEP);

	mutex_enter(&lx_sysfs_mount_lock);

	/*
	 * Do not allow overlaying mounts.
	 */
	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		mutex_exit(&lx_sysfs_mount_lock);
		kmem_free(lxmnt, sizeof (*lxmnt));
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * Allocate the sysfs node for the root of the mount, using the
	 * mountpoint (a directory) as the parent vnode:
	 */
	lxmnt->lxsys_root = lx_sysfs_node_alloc(mvp, LX_SYSFS_NT_ROOT);
	/*
	 * Reset vfsp for the root node to this (not the parent) filesystem:
	 */
	lxmnt->lxsys_root->lxsn_vnode->v_vfsp = vfsp;

	vfs_make_fsid(&vfsp->vfs_fsid, lx_sysfs_dev, lx_sysfs_fstype);
	vfsp->vfs_bsize = DEV_BSIZE;
	vfsp->vfs_fstype = lx_sysfs_fstype;
	vfsp->vfs_data = (caddr_t)lxmnt;
	vfsp->vfs_dev = lx_sysfs_dev;

	mutex_exit(&lx_sysfs_mount_lock);

	return (0);
}

static int
lx_sysfs_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	lx_sysfs_mount_t *lxmnt = (lx_sysfs_mount_t *)vfsp->vfs_data;
	vnode_t *vp;

	VERIFY(lxmnt != NULL);
	vp = lxmnt->lxsys_root->lxsn_vnode;

	mutex_enter(&lx_sysfs_mount_lock);

	/*
	 * Check for permission to unmount:
	 */
	if (secpolicy_fs_unmount(cr, vfsp) != 0) {
		mutex_exit(&lx_sysfs_mount_lock);
		return (EPERM);
	}

	if (flag & MS_FORCE) {
		/*
		 * Forced unmounting is not supported.
		 */
		mutex_exit(&lx_sysfs_mount_lock);
		return (ENOTSUP);
	}

	/*
	 * Ensure that the filesystem is no longer in use:
	 */
	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1) {
		mutex_exit(&vp->v_lock);
		mutex_exit(&lx_sysfs_mount_lock);
		return (EBUSY);
	}
	mutex_exit(&vp->v_lock);

	dnlc_purge_vfsp(vfsp, 0);

	kmem_free(lxmnt, sizeof (*lxmnt));

	mutex_exit(&lx_sysfs_mount_lock);
	return (0);
}

static int
lx_sysfs_root(vfs_t *vfsp, vnode_t **vpp)
{
	lx_sysfs_mount_t *lxmnt = (lx_sysfs_mount_t *)vfsp->vfs_data;
	lx_sysfs_node_t *lxsn = lxmnt->lxsys_root;
	vnode_t *vp = lxsn->lxsn_vnode;

	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

static int
lx_sysfs_statvfs(vfs_t *vfsp, statvfs64_t *sp)
{
	dev32_t d32;

	bzero(sp, sizeof (*sp));
	sp->f_bsize = DEV_BSIZE;
	sp->f_frsize = DEV_BSIZE;

	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid = d32;

	(void) snprintf(sp->f_basetype, sizeof (sp->f_basetype), "%s",
	    vfssw[lx_sysfs_fstype].vsw_name);
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = 64;
	(void) snprintf(sp->f_fstr, sizeof (sp->f_fstr), "/sys");

	return (0);
}
