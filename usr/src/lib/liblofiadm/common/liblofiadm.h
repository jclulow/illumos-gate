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

#include <sys/types.h>
#include <stdbool.h>

/*
 * Public library interface for managing lofi(7D) devices.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum lofiadm_error {
	LOFIADM_ERR_OK = 0,
	LOFIADM_ERR_INVALID_FLAGS,
	LOFIADM_ERR_NOT_WALKING,
	LOFIADM_ERR_PATH_TOO_LONG,
	LOFIADM_ERR_MEMORY_ALLOC,
	LOFIADM_ERR_READONLY,
	LOFIADM_ERR_ACCESS,
	LOFIADM_ERR_DEVICE,
	LOFIADM_ERR_INTERNAL,
	LOFIADM_ERR_NO_FILE_MATCH,
	LOFIADM_ERR_NO_DEVICE_MATCH,
} lofiadm_error_t;

#define	LOFIADM_F_READONLY	0
#define	LOFIADM_F_READWRITE	(1U << 0)

#define	LOFIADM_F_VALID		(LOFIADM_F_READWRITE | LOFIADM_F_READONLY)

typedef struct lofiadm lofiadm_t;

extern lofiadm_error_t lofiadm_init(lofiadm_t **, uint_t);
extern void lofiadm_fini(lofiadm_t *);

extern void lofiadm_reset(lofiadm_t *);
extern bool lofiadm_walk(lofiadm_t *);
extern bool lofiadm_walk_next(lofiadm_t *);

extern lofiadm_error_t lofiadm_error(lofiadm_t *);
extern const char *lofiadm_strerror(lofiadm_error_t);

extern bool lofiadm_ent_readonly(lofiadm_t *);
extern bool lofiadm_ent_label(lofiadm_t *);
extern bool lofiadm_ent_compressed(lofiadm_t *);
extern bool lofiadm_ent_encrypted(lofiadm_t *);
extern const char *lofiadm_ent_filename(lofiadm_t *);
extern const char *lofiadm_ent_rdevpath(lofiadm_t *);
extern const char *lofiadm_ent_devpath(lofiadm_t *);
extern const char *lofiadm_ent_compression(lofiadm_t *);

extern bool lofiadm_lookup_file(lofiadm_t *, const char *);
extern bool lofiadm_lookup_device(lofiadm_t *, const char *);

/*
 * Private routines for lofiadm(1M):
 */
extern int lofiadm_fd(lofiadm_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBLOFIADM_H */
