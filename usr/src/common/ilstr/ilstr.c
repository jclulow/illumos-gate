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

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#endif
#include <sys/debug.h>

#include "ilstr.h"

void
ilstr_init(ilstr_t *ils, int kmflag)
{
	bzero(ils, sizeof (*ils));
	ils->ils_kmflag = kmflag;
}

void
ilstr_reset(ilstr_t *ils)
{
	if (ils->ils_strlen > 0) {
		/*
		 * Truncate the string but do not free the buffer so that we
		 * can use it again without further allocation.
		 */
		ils->ils_data[0] = '\0';
		ils->ils_strlen = 0;
	}
	ils->ils_errno = ILSTR_ERROR_OK;
}

void
ilstr_fini(ilstr_t *ils)
{
	if (ils->ils_data != NULL) {
#ifdef _KERNEL
		kmem_free(ils->ils_data, ils->ils_datalen);
#else
		free(ils->ils_data);
#endif
	}
}

void
ilstr_append_str(ilstr_t *ils, const char *s)
{
	ilstr_append_strn(ils, s, SIZE_MAX);
}

void
ilstr_append_strn(ilstr_t *ils, const char *s, size_t maxlen)
{
	size_t len;
	size_t chunksz = 64;

	if (ils->ils_errno != ILSTR_ERROR_OK) {
		return;
	}

	if ((len = strlen(s)) < 1) {
		return;
	}

	if (len > maxlen) {
		len = maxlen;
	}

	/*
	 * Check to ensure that the new string length does not overflow,
	 * leaving room for the termination byte:
	 */
	if (len >= SIZE_MAX - ils->ils_strlen - 1) {
		ils->ils_errno = ILSTR_ERROR_OVERFLOW;
		return;
	}
	size_t new_strlen = ils->ils_strlen + len;

	if (new_strlen + 1 >= ils->ils_datalen) {
		size_t new_datalen = ils->ils_datalen;
		char *new_data;

		/*
		 * Grow the string buffer to make room for the new string.
		 */
		while (new_datalen < new_strlen + 1) {
			if (chunksz >= SIZE_MAX - new_datalen) {
				ils->ils_errno = ILSTR_ERROR_OVERFLOW;
				return;
			}
			new_datalen += chunksz;
		}

#ifdef _KERNEL
		new_data = kmem_alloc(new_datalen, ils->ils_kmflag);
#else
		new_data = malloc(new_datalen);
#endif
		if (new_data == NULL) {
			ils->ils_errno = ILSTR_ERROR_NOMEM;
			return;
		}

		if (ils->ils_data != NULL) {
			bcopy(ils->ils_data, new_data, ils->ils_strlen + 1);
#ifdef _KERNEL
			kmem_free(ils->ils_data, ils->ils_datalen);
#else
			free(ils->ils_data);
#endif
		}

		ils->ils_data = new_data;
		ils->ils_datalen = new_datalen;
	}

	bcopy(s, ils->ils_data + ils->ils_strlen, len + 1);
	ils->ils_strlen = new_strlen;
}

void
ilstr_append_uint(ilstr_t *ils, uint_t n)
{
	char buf[64];

	if (ils->ils_errno != ILSTR_ERROR_OK) {
		return;
	}

	VERIFY3U(snprintf(buf, sizeof (buf), "%u", n), <, sizeof (buf));

	ilstr_append_str(ils, buf);
}

void
ilstr_append_char(ilstr_t *ils, char c)
{
	char buf[2];

	if (ils->ils_errno != ILSTR_ERROR_OK) {
		return;
	}

	buf[0] = c;
	buf[1] = '\0';

	ilstr_append_str(ils, buf);
}

ilstr_errno_t
ilstr_errno(ilstr_t *ils)
{
	return (ils->ils_errno);
}

const char *
ilstr_cstr(ilstr_t *ils)
{
	return (ils->ils_data);
}

size_t
ilstr_len(ilstr_t *ils)
{
	return (ils->ils_strlen);
}

const char *
ilstr_errstr(ilstr_t *ils)
{
	switch (ils->ils_errno) {
	case ILSTR_ERROR_OK:
		return ("ok");
	case ILSTR_ERROR_NOMEM:
		return ("could not allocate memory");
	case ILSTR_ERROR_OVERFLOW:
		return ("tried to construct too large a string");
	default:
		return ("unknown error");
	}
}
