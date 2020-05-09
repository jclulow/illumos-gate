/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "tmextern.h"

/*
 * getword	- extract one token from the string
 *		- token delimiter is white space if getall is FALSE
 *		- token delimiter is ':' or '\0' if getall is TRUE
 */
char *
getword(const char *ptr, size_t *size, bool getall)
{
	char *optr, c;
	char word[BUFSIZ];
	size_t qsize;
	size_t internal;

	if (size == NULL) {
		size = &internal;
	}

	*size = 0;
	if (!getall) {
		/* Skip all white spaces */
		while (isspace(*ptr)) {
			(*size)++;
			ptr++;
		}
	}

	/* Put all characters from here to next white space or ':' or '\0' */
	/* into the word, up to the size of the word. */
	for (optr = word, *optr = '\0'; 
	    *ptr != '\0' && *ptr != ':';
	    ptr++, (*size)++) {
		if (!getall) {
			if (isspace(*ptr))
				break;
		}

		/* If the character is quoted, analyze it. */
		if (*ptr == '\\') {
			c = quoted(ptr, &qsize);
			(*size) += qsize;
			ptr += qsize;
		} else {
			c = *ptr;
		}

		/* If there is room, add this character to the word. */
		if (optr < &word[BUFSIZ]) {
			*optr++ = c;
		}
	}

	/* skip trailing blanks if any*/
	while (isspace(*ptr)) {
		(*size)++;
		ptr++;
	}

	/* Make sure the line is null terminated. */
	*optr++ = '\0';
	return (safe_strdup(word));
}

/*
 * "quoted" takes a quoted character, starting at the quote character, and
 * returns a single character plus the size of the quote string.  "quoted"
 * recognizes the following as special: \n, \r, \v, \t, \b, \f, and the \nnn
 * notation.
 */
char 
quoted(const char *ptr, size_t *qsize)
{
	char c;
	const char *rptr = ptr;
	int i;

	switch (*++rptr) {
	case 'n':
		c = '\n';
		break;
	case 'r':
		c = '\r';
		break;
	case 'v':
		c = '\013';
		break;
	case 'b':
		c = '\b';
		break;
	case 't':
		c = '\t';
		break;
	case 'f':
		c = '\f';
		break;
	case ':':
		c = ':';
		break;
	default:
		/*
		 * If this is a numeric string, take up to three characters of
		 * it as the value of the quoted character.
		 */
		if (*rptr >= '0' && *rptr <= '7') {
			for (i = 0, c = 0; i < 3; i++) {
				c = c * 8 + (*rptr - '0');
				if (*++rptr < '0' || *rptr > '7')
					break;
			}
			rptr--;

		/*
		 * If the character following the '\\' is a NULL, back up the
		 * ptr so that the NULL won't be missed.  The sequence
		 * backslash null is essentially illegal.
		 */
		} else if (*rptr == '\0') {
			c = '\0';
			rptr--;

		/*
		 * In all other cases the quoting does nothing.
		 */
		} else {
			c = *rptr;
		}
		break;
	}

	/*
	 * Compute the size of the quoted character.
	 */
	(*qsize) = rptr - ptr; 
	return (c);
}

bool
walk_table(const char *path, void (*linefunc)(uint_t, const char *),
    time_t *mtime)
{
	FILE *f;
	if ((f = fopen(path, "r")) == NULL) {
		log("cannot open %s: %s", path, strerror(errno));
		return (false);
	}

	if (mtime != NULL) {
		struct stat st;
		if (fstat(fileno(f), &st) != 0) {
			log("cannot stat %s: %s", path, strerror(errno));
			(void) fclose(f);
			return (false);
		}

		*mtime = st.st_mtime;
	}

	uint_t linenum = 0;
	char *line = NULL;
	size_t cap = 0;
	for (;;) {
		ssize_t sz;
		errno = 0;
		if ((sz = getline(&line, &cap, f)) <= 0) {
			if (errno != 0) {
				log("error reading from %s: %s", path,
				    strerror(errno));
			}

			/*
			 * Whether due to a failure or not, we have read
			 * all that we can.
			 */
			break;
		}

		/*
		 * Remove any trailing linefeeds:
		 */
		while (sz > 0 && line[sz - 1] == '\n') {
			line[sz - 1] = '\0';
			sz--;
		}

		/*
		 * Look for a comment in the string.  If we find one, remove
		 * from there to the end of the line.  The comment character
		 * may be escaped with a backslash.
		 */
		char prev = '\0';
		for (size_t i = 0; line[i] != '\0'; i++) {
			if (line[i] == '#' && prev != '\\') {
				line[i] = '\0';
				break;
			}
			prev = line[i];
		}

		linenum++;

		/*
		 * Skip lines that consist only of whitespace characters:
		 */
		bool blank = true;
		for (size_t i = 0; line[i] != '\0'; i++) {
			if (isspace(line[i])) {
				blank = false;
				break;
			}
		}
		if (blank) {
			continue;
		}

		linefunc(linenum, line);
	}

	free(line);
	return (true);
}
