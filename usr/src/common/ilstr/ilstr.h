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
#ifndef _PROTOTYPE_H
#define	_PROTOTYPE_H

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#endif
#include <sys/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ilstr_errno {
	ILSTR_ERROR_OK = 0,
	ILSTR_ERROR_NOMEM,
	ILSTR_ERROR_OVERFLOW,
} ilstr_errno_t;

typedef struct ilstr {
	char *ils_data;
	size_t ils_datalen;
	size_t ils_strlen;
	uint_t ils_errno;
	int ils_kmflag;
} ilstr_t;

extern void ilstr_init(ilstr_t *ils, int kmflag);
extern void ilstr_fini(ilstr_t *ils);

extern void ilstr_reset(ilstr_t *ils);

extern void ilstr_append_str(ilstr_t *ils, const char *s);
extern void ilstr_append_strn(ilstr_t *ils, const char *s, size_t n);
extern void ilstr_append_uint(ilstr_t *ils, uint_t n);
extern void ilstr_append_char(ilstr_t *ils, char c);

extern const char *ilstr_cstr(ilstr_t *ils);
extern size_t ilstr_len(ilstr_t *ils);

extern ilstr_errno_t ilstr_errno(ilstr_t *ils);
extern const char *ilstr_errstr(ilstr_t *ils);

#ifdef __cplusplus
}
#endif

#endif /* _PROTOTYPE_H */
