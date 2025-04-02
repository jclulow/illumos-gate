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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _VEC_H
#define	_VEC_H

/*
 * vec_t is a basic data structure for keeping a list of pointers that may
 * expand over time.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vec vec_t;

extern vec_t *vec_alloc(void);
extern void vec_free(vec_t *);
extern int vec_push(vec_t *, void *);
extern void *vec_pop(vec_t *);
extern size_t vec_len(const vec_t *);
extern void *vec_get(const vec_t *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _VEC_H */
