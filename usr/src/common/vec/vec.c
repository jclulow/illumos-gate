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

/*
 * vec_t is a basic data structure for keeping a list of pointers that may
 * expand over time.
 */

#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <sys/debug.h>
#include "vec.h"

struct vec {
	void **v_pointers;
	size_t v_cap;
	size_t v_len;
};

static int vec_have_space(vec_t *, size_t);

vec_t *
vec_alloc(void)
{
	vec_t *v = calloc(1, sizeof (*v));
	if (v == NULL) {
		return (NULL);
	}

	/*
	 * Give the vector an initial capacity of 8 pointers, if we can:
	 */
	(void) vec_have_space(v, 8);

	return (v);
}

void
vec_free(vec_t *v)
{
	if (v == NULL) {
		return;
	}

	if (v->v_len != 0) {
		const char *msg = "must empty vec_t before calling vec_free()";

		upanic(msg, sizeof (msg));
	}

	free(v);
}

static int
vec_have_space(vec_t *v, size_t needelems)
{
	VERIFY3U(v->v_len, <=, v->v_cap);

	/*
	 * Check to ensure the new vector count does not overflow, leaving room
	 * for a NULL pointer in the slot one past our current occupied length:
	 */
	if (needelems >= SIZE_MAX - v->v_len - 1) {
		errno = EOVERFLOW;
		return (-1);
	}
	size_t new_len = v->v_len + needelems;

	if (new_len + 1 > v->v_cap) {
		size_t new_cap = v->v_cap;

		while (new_cap < new_len + 1) {
			if (SIZE_MAX - new_len < 8) {
				errno = EOVERFLOW;
				return (-1);
			}
			new_cap += 8;
		}

		void **new_pointers = recallocarray(v->v_pointers, v->v_cap,
		    new_cap, sizeof (v->v_pointers[0]));
		if (new_pointers == NULL) {
			if (errno == EINVAL) {
				errno = EOVERFLOW;
			}
			return (-1);
		}

		v->v_pointers = new_pointers;
		v->v_cap = new_cap;
	}

	return (0);
}

int
vec_push(vec_t *v, void *item)
{
	if (vec_have_space(v, 1) != 0) {
		return (-1);
	}

	v->v_pointers[v->v_len++] = item;

	return (0);
}

void *
vec_pop(vec_t *v)
{
	if (v->v_len < 1) {
		return (NULL);
	}

	void *r = v->v_pointers[--v->v_len];
	v->v_pointers[v->v_len] = NULL;

	return (r);
}

size_t
vec_len(const vec_t *v)
{
	return (v->v_len);
}

void *
vec_get(const vec_t *v, size_t index)
{
	if (index >= v->v_len) {
		return (NULL);
	}

	return (v->v_pointers[index]);
}
