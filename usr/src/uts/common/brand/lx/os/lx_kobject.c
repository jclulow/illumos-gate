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
 * Provide an analogue to the Linux "kobject" hierarchy.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/lx_brand.h>
#include <sys/lx_kobject.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>

lx_kobject_t *
lx_kobject_alloc(lx_kobject_t *parent, const char *name)
{
	lx_kobject_t *lxko;

	lxko = kmem_zalloc(sizeof (*lxko), KM_SLEEP);
	lxko->lxko_name = name;
	lxko->lxko_parent = parent;
	list_create(&lxko->lxko_children, sizeof (lx_kobject_t),
	    offsetof(lx_kobject_t, lxko_linkage));

	return (lxko);
}

void
lx_kobject_free(lx_kobject_t *lxko)
{
	lx_kobject_t *rlxko;

	while ((rlxko = list_head(&lxko->lxko_children)) != NULL) {
		list_remove(&lxko->lxko_children, rlxko);
		lx_kobject_free(rlxko);
	}

	kmem_free(lxko, sizeof (*lxko));
}

lx_kobject_t *
lx_kobject_lookup_locked(zone_t *z, lx_kobject_t *parent, const char *name)
{
	lx_zone_data_t *lxzd = (lx_zone_data_t *)z->zone_brand_data;
	lx_kobject_t *lxko;

	VERIFY3P(lxzd, !=, NULL);
	VERIFY(MUTEX_HELD(&lxzd->lxzd_kobject_lock));

	if (parent == NULL) {
		VERIFY(lxzd->lxzd_kobject_root != NULL);
		return (lxzd->lxzd_kobject_root);
	}

	for (lxko = list_head(&parent->lxko_children); lxko != NULL;
	    lxko = list_next(&parent->lxko_children, lxko)) {
		if (strcmp(lxko->lxko_name, name) == 0) {
			return (lxko);
		}
	}

	return (NULL);
}

lx_kobject_t *
lx_kobject_lookup(zone_t *z, lx_kobject_t *parent, const char *name)
{
	lx_zone_data_t *lxzd = (lx_zone_data_t *)z->zone_brand_data;
	lx_kobject_t *lxko;

	VERIFY3P(lxzd, !=, NULL);
	VERIFY(MUTEX_NOT_HELD(&lxzd->lxzd_kobject_lock));

	mutex_enter(&lxzd->lxzd_kobject_lock);
	lxko = lx_kobject_lookup_locked(z, parent, name);
	mutex_exit(&lxzd->lxzd_kobject_lock);

	return (lxko);
}

lx_kobject_t *
lx_kobject_lookup_index(zone_t *z, lx_kobject_t *parent, unsigned long idx)
{
	lx_zone_data_t *lxzd = (lx_zone_data_t *)z->zone_brand_data;
	lx_kobject_t *lxko;

	VERIFY3P(lxzd, !=, NULL);
	VERIFY(MUTEX_NOT_HELD(&lxzd->lxzd_kobject_lock));

	mutex_enter(&lxzd->lxzd_kobject_lock);
	for (lxko = list_head(&parent->lxko_children); lxko != NULL;
	    lxko = list_next(&parent->lxko_children, lxko)) {
		if (idx-- == 0) {
			/*
			 * This is the index we want.
			 */
			break;
		}
	}
	mutex_exit(&lxzd->lxzd_kobject_lock);

	return (lxko);
}

lx_kobject_t *
lx_kobject_add(zone_t *z, lx_kobject_t *parent, const char *name)
{
	lx_zone_data_t *lxzd = (lx_zone_data_t *)z->zone_brand_data;
	lx_kobject_t *lxko, *rlxko;

	VERIFY(lxzd != NULL);
	VERIFY(MUTEX_NOT_HELD(&lxzd->lxzd_kobject_lock));

	if (parent == NULL) {
		mutex_enter(&lxzd->lxzd_kobject_lock);
		/*
		 * Add to the top-level list:
		 */
		VERIFY(lxzd->lxzd_kobject_root != NULL);
		parent = lxzd->lxzd_kobject_root;
		mutex_exit(&lxzd->lxzd_kobject_lock);
	}

	lxko = lx_kobject_alloc(parent, name);

	mutex_enter(&lxzd->lxzd_kobject_lock);
	if ((rlxko = lx_kobject_lookup_locked(z, parent, name)) == NULL) {
		/*
		 * An object with this name does not exist; insert the one
		 * we just allocated.
		 */
		list_insert_tail(&parent->lxko_children, lxko);
		lxko->lxko_id = lxzd->lxko_kobject_nextid++;
		parent->lxko_nchildren++;
	}
	mutex_exit(&lxzd->lxzd_kobject_lock);

	if (rlxko != NULL) {
		/*
		 * An object with this name already existed; the object we
		 * allocated is surplus to requirements.
		 */
		kmem_free(lxko, sizeof (*lxko));
		lxko = rlxko;
	}

	return (lxko);
}
