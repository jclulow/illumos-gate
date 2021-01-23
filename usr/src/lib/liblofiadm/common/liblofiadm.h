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
 * Copyright 2021 Oxide Computer Company
 */

#ifndef _LIBLOFIADM_H
#define	_LIBLOFIADM_H

/*
 * Public library interface for managing lofi(7D) devices.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lofiadm lofiadm_t;
typedef struct lofiwalk lofiwalk_t;

extern int lofiadm_init(lofiadm_t **);
extern void lofiadm_fini(lofiadm_t *);

extern int lofiadm_walk_alloc(lofiadm_t *, lofiwalk_t **);
extern void lofiadm_walk_free(lofiwalk_t *);
extern int lofiadm_walk_step(lofiwalk_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBLOFIADM_H */
