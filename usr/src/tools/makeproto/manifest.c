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

/*
 * XXX Describe the purpose of this file.
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/debug.h>
#include <libcustr.h>

#include "manifest.h"

static int
parse_line(const char *line, strlist_t *sl)
{
	custr_t *cu = NULL;
	const char *c = line;
	int e = 0;
	enum {
		ST_WHITESPACE,
		ST_FIELD,
		ST_ESCAPE,
		ST_COMMENT,
	} state = ST_WHITESPACE;

	if (custr_alloc(&cu) != 0) {
		e = errno;
		goto out;
	}

	for (;;) {
		char cc = *c;
		boolean_t is_space = B_FALSE;

		if (cc == ' ' || cc == '\t' || cc == '\r' || cc == '\n') {
			is_space = B_TRUE;
		}

		switch (state) {
		case ST_COMMENT:
			if (cc == '\0') {
				goto out;
			}
			c++;
			continue;

		case ST_WHITESPACE:
			if (cc == '\0') {
				goto out;
			} else if (is_space) {
				c++;
			} else if (cc == '#') {
				state = ST_COMMENT;
				c++;
			} else {
				state = ST_FIELD;
			}
			continue;

		case ST_FIELD:
			if (cc == '\\') {
				state = ST_ESCAPE;
			} else if (is_space || cc == '\0') {
				if (custr_len(cu) > 0 &&
				    strlist_set_tail(sl, custr_cstr(cu)) != 0) {
					e = errno;
					goto out;
				}
				custr_reset(cu);
				state = ST_WHITESPACE;
			} else {
				if (custr_appendc(cu, cc) != 0) {
					e = errno;
					goto out;
				}
				c++;
			}
			continue;

		case ST_ESCAPE:
			if (cc == '\\' || cc == ' ') {
				if (custr_appendc(cu, cc) != 0) {
					e = errno;
					goto out;
				}
				state = ST_FIELD;
				c++;
			} else {
				e = EPROTO;
				goto out;
			}
			continue;
		}
	}

out:
	custr_free(cu);
	errno = e;
	return (e == 0 ? 0 : -1);
}

int
manifest_read(const char *path, manifest_ent_cb_t *mecb, void *arg)
{
	FILE *mf = NULL;
	char *line = NULL;
	size_t cap = 0;
	strlist_t *sl = NULL;
	int e = 0;
	int r = -1;

	if (strlist_alloc(&sl, 0) != 0) {
		e = errno;
		goto out;
	}

	if ((mf = fopen(path, "r")) == NULL) {
		e = errno;
		goto out;
	}

	for (;;) {
		strlist_reset(sl);
		ssize_t ssz;

		errno = 0;
		if ((ssz = getline(&line, &cap, mf)) < 0) {
			if (errno == 0) {
				/*
				 * End of file reached.
				 */
				r = 0;
				goto out;
			}

			/*
			 * Some other error:
			 */
			e = errno;
			goto out;
		}

		/*
		 * Strip trailing newlines from lines.
		 */
		while (ssz > 0 && line[ssz - 1] == '\n') {
			line[ssz - 1] = '\0';
			ssz--;
		}

		if (parse_line(line, sl) != 0) {
			e = errno;
			goto out;
		}

		if (strlist_contig_count(sl) == 0) {
			/*
			 * No fields on this line.
			 */
			continue;
		}

		switch (mecb(line, sl, arg)) {
		case MECB_NEXT:
			continue;

		case MECB_CANCEL:
			e = ECANCELED;
			goto out;

		case MECB_DONE:
			r = 0;
			goto out;
		}
	}

out:
	if (mf != NULL) {
		(void) fclose(mf);
	}
	free(line);
	strlist_free(sl);
	errno = e;
	return (r);
}

int
manifest_macro_expand(const char *input, strmap_t *macros, custr_t *out)
{
	const char *c = input;
	int e = 0;
	enum {
		ST_REST,
		ST_DOLLAR,
		ST_MACRO,
	} state = ST_REST;
	custr_t *macro = NULL;

	custr_reset(out);

	if (custr_alloc(&macro) != 0) {
		e = errno;
		goto out;
	}

	for (;;) {
		char cc = *c;

		switch (state) {
		case ST_REST:
			if (cc == '\0') {
				goto out;

			} else if (cc == '$') {
				state = ST_DOLLAR;

			} else {
				if (custr_appendc(out, cc) != 0) {
					e = errno;
					goto out;
				}
			}
			c++;
			continue;

		case ST_DOLLAR:
			if (cc == '$') {
				/*
				 * An escaped literal dollar sign.
				 */
				if (custr_appendc(out, cc) != 0) {
					e = errno;
					goto out;
				}

			} else if (cc == '(') {
				/*
				 * The start of a macro to expand.
				 */
				state = ST_MACRO;
				custr_reset(macro);

			} else {
				/*
				 * Fail to expand input that is not
				 * well-formed.
				 */
				e = EPROTO;
				goto out;
			}
			c++;
			continue;

		case ST_MACRO:
			if (cc == '\0') {
				e = EPROTO;
				goto out;

			} else if (cc == '$' || cc == '(') {
				/*
				 * We do not support nested macro expansion
				 * at this time.
				 */
				e = EPROTO;
				goto out;

			} else if (cc == ')') {
				/*
				 * Look up the macro name we have collected.
				 */
				const char *val = strmap_get(macros,
				    custr_cstr(macro));

				if (val == NULL) {
					VERIFY3S(errno, ==, ENOENT);
				} else if (custr_append(out, val) != 0) {
					e = errno;
					goto out;
				}

				state = ST_REST;

			} else {
				if (custr_appendc(macro, cc) != 0) {
					e = errno;
					goto out;
				}
			}
			c++;
			continue;
		}
	}

out:
	custr_free(macro);
	errno = e;
	return (e == 0 ? 0 : -1);
}
