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

#ifndef _MANIFEST_H
#define	_MANIFEST_H

/*
 * XXX Describe the purpose of the file here.
 */

#include <libcustr.h>
#include <strlist.h>
#include <strmap.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum me_cb_ret {
	MECB_NEXT = 1,
	MECB_DONE,
	MECB_CANCEL
} me_cb_ret_t;

typedef me_cb_ret_t manifest_ent_cb_t(const char *, strlist_t *, void *);

extern int manifest_read(const char *, manifest_ent_cb_t *, void *);
extern int manifest_macro_expand(const char *, strmap_t *, custr_t *);

#ifdef __cplusplus
}
#endif

#endif /* _MANIFEST_H */
