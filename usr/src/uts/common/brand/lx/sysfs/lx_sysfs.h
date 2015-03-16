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

#ifndef _LX_SYSFS_H
#define	_LX_SYSFS_H

#include <sys/vnode.h>
#include <sys/lx_brand.h>
#include <sys/lx_kobject.h>

/*
 * Definitions for LX brand "sysfs" emulation.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lx_sysfs_node lx_sysfs_node_t;
typedef struct lx_sysfs_mount lx_sysfs_mount_t;

/*
 * Per-vnode Private Data
 */
struct lx_sysfs_node {
	lx_sysfs_mount_t	*lxsn_mount;
	vnode_t			*lxsn_vnode;
	vnode_t			*lxsn_parent;
	timestruc_t		lxsn_time;
	lx_kobject_t		*lxsn_kobject;
};

/*
 * Per-filesystem Private Data
 */
struct lx_sysfs_mount {
	lx_sysfs_node_t		*lxsys_root;	/* fs root node */
	zone_t			*lxsys_zone;
};

extern vnodeops_t *lx_sysfs_vnodeops;

extern void lx_sysfs_common_init(void);
extern void lx_sysfs_common_fini(void);
extern lx_sysfs_node_t *lx_sysfs_node_alloc(lx_sysfs_mount_t *, vnode_t *,
    boolean_t, lx_kobject_t *);
extern void lx_sysfs_node_free(lx_sysfs_node_t *);
extern ino64_t lx_sysfs_inode(lx_kobject_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LX_SYSFS_H */

#if 0
/*
 * This is the lxprocfs private data object
 * which is attached to v_data in the vnode structure
 */
typedef struct lxpr_node {
	lxpr_nodetype_t	lxpr_type;	/* type of this node 		*/
	vnode_t		*lxpr_vnode;	/* vnode for the node		*/
	vnode_t		*lxpr_parent;	/* parent directory		*/
	vnode_t		*lxpr_realvp;	/* real vnode, file in dirs	*/
	timestruc_t	lxpr_time;	/* creation etc time for file	*/
	mode_t		lxpr_mode;	/* file mode bits		*/
	uid_t		lxpr_uid;	/* file owner			*/
	gid_t		lxpr_gid;	/* file group owner		*/
	pid_t		lxpr_pid;	/* pid of proc referred to	*/
	uint_t		lxpr_desc;	/* addl. descriptor (fd or tid)	*/
	ino_t		lxpr_ino;	/* node id 			*/
	ldi_handle_t	lxpr_cons_ldih; /* ldi handle for console device */
} lxpr_node_t;

struct zone;    /* forward declaration */

/*
 * This is the lxprocfs private data object
 * which is attached to vfs_data in the vfs structure
 */
typedef struct lxpr_mnt {
	lxpr_node_t	*lxprm_node;	/* node at root of proc mount */
	struct zone	*lxprm_zone;	/* zone for this mount */
	ldi_ident_t	lxprm_li;	/* ident for ldi */
} lxpr_mnt_t;

extern vnodeops_t	*lxpr_vnodeops;
extern int		nproc_highbit;	/* highbit(v.v_nproc)		*/

typedef struct mounta	mounta_t;

#endif
