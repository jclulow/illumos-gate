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
read_manifest_file(const char *path, manifest_ent_cb_t *mecb, void *arg)
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
			e = EINTR;
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
