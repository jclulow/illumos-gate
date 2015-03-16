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

#ifndef _LX_KOBJECT_H
#define	_LX_KOBJECT_H

#include <sys/list.h>

/*
 * LX Brand: Linux "kobject" hierarchy emulation.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lx_kobject lx_kobject_t;

struct lx_kobject {
	unsigned long	lxko_id;
	const char	*lxko_name;
	lx_kobject_t	*lxko_parent;
	unsigned int	lxko_nchildren;
	list_t		lxko_children;
	list_node_t	lxko_linkage;
};

extern lx_kobject_t *lx_kobject_alloc(lx_kobject_t *, const char *);
extern void lx_kobject_free(lx_kobject_t *);

extern lx_kobject_t *lx_kobject_lookup_locked(zone_t *, lx_kobject_t *,
    const char *);
extern lx_kobject_t *lx_kobject_lookup(zone_t *, lx_kobject_t *, const char *);
extern lx_kobject_t *lx_kobject_lookup_index(zone_t *, lx_kobject_t *,
    unsigned long);

extern lx_kobject_t *lx_kobject_add(zone_t *, lx_kobject_t *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _LX_KOBJECT_H */
