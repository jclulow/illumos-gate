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
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _STRMAP_H
#define	_STRMAP_H

/*
 * A map from string keys to string values (strmap_t).
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum strmap_flags {
	STRMAP_F_CASE_INSENSITIVE =	(0x1 << 0),
	STRMAP_F_UNIQUE_NAMES =		(0x1 << 1),
} strmap_flags_t;

#define	STRMAP_F_VALID			(STRMAP_F_CASE_INSENSITIVE | \
					    STRMAP_F_UNIQUE_NAMES)

typedef struct strmap strmap_t;
typedef struct strmap_ent strmap_ent_t;

extern int strmap_alloc(strmap_t **, uint32_t);
extern void strmap_free(strmap_t *);
extern strmap_ent_t *strmap_next(strmap_t *, strmap_ent_t *);
extern const char *strmap_ent_key(strmap_ent_t *);
extern const char *strmap_ent_value(strmap_ent_t *);
extern void strmap_clear(strmap_t *);
extern const char *strmap_get(strmap_t *, const char *);
extern int strmap_add(strmap_t *, const char *, const char *);
extern bool strmap_empty(strmap_t *);

#ifdef __cplusplus
}
#endif

#endif /* _STRMAP_H */
