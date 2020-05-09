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
 * Copyright 2020 Oxide Computer Company
 */

#ifndef _SYS_ILSTR_H
#define	_SYS_ILSTR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

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

extern void ilstr_init(ilstr_t *, int);
extern void ilstr_reset(ilstr_t *);
extern void ilstr_fini(ilstr_t *);
extern void ilstr_append_str(ilstr_t *, const char *);
extern void ilstr_append_uint(ilstr_t *, uint_t);
extern void ilstr_append_char(ilstr_t *, char);
extern ilstr_errno_t ilstr_errno(ilstr_t *);
extern const char *ilstr_cstr(ilstr_t *);
extern size_t ilstr_len(ilstr_t *);
extern const char *ilstr_errstr(ilstr_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ILSTR_H */
