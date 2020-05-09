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
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termio.h>
#include <sys/stermio.h>
#include <sys/termiox.h>
#include <sys/avl.h>
#include <sys/debug.h>
#include <sys/ilstr.h>
#include <strlist.h>
#include "ttymon.h"
#include "tmstruct.h"
#include "tmextern.h"
#include "stty.h"

static bool g_defs_init = false;
static avl_tree_t g_defs;
static time_t g_ttydefs_mtime = 0;
static struct Gdef *g_defs_head = NULL;
static struct Gdef *g_defs_tail = NULL;

static void insert_def(struct Gdef *);
static struct Gdef *alloc_def(void);
static void free_def(struct Gdef *);

typedef enum {
	T_TTYLABEL = 1,
	T_IFLAGS,
	T_FFLAGS,
	T_AUTOBAUD,
	T_NEXTLABEL,
} ttydefs_field_t;

const char *
ttydefs_field_name(ttydefs_field_t f)
{
	switch (f) {
	case T_TTYLABEL:
		return ("tty label");
	case T_IFLAGS:
		return ("initial flags");
	case T_FFLAGS:
		return ("final flags");
	case T_AUTOBAUD:
		return ("autobaud");
	case T_NEXTLABEL:
		return ("next label");
	}

	abort();
}

void
print_ttydef(const struct Gdef *g)
{
	size_t len = strlen(g->g_line);

	char *ruler = malloc(len + 1);
	memset(ruler, '-', len);
	ruler[len] = '\0';

	log("\n%s", ruler);
	log("%s", g->g_line);
	log("%s\n", ruler);

	free(ruler);

	log("ttylabel:\t%s", g->g_id);
	log("initial flags:\t%s", g->g_iflags);
	log("final flags:\t%s", g->g_fflags);
	if (g->g_autobaud & A_FLAG) {
		log("autobaud:\tyes");
	} else {
		log("autobaud:\tno");
	}
	log("nextlabel:\t%s", g->g_nextid);
}

bool
check_ttydefs(const char *label)
{
	VERIFY(g_defs_init);

	if (label != NULL) {
		const struct Gdef *g;

		if ((g = find_def(label)) == NULL) {
			return (false);
		}

		print_ttydef(g);
		return (true);
	}

	for (struct Gdef *g = avl_first(&g_defs); g != NULL;
	    g = AVL_NEXT(&g_defs, g)) {
		print_ttydef(g);
	}

	return (true);
}

/*
 * Returns true if we should re-read /etc/ttydefs, and false if not.
 */
bool
mod_ttydefs(void)
{
	if (g_ttydefs_mtime == 0) {
		/*
		 * We have not yet read the file at all.
		 */
		return (true);
	}

	struct stat st;
	if (stat(TTYDEFS, &st) != 0) {
		/*
		 * We could not see the file, so we probably cannot re-read it.
		 */
		return (false);
	}

	/*
	 * Re-read it if it has changed since we read it last:
	 */
	return (st.st_mtime != g_ttydefs_mtime);
}

static int
g_defs_compare(const void *l, const void *r)
{
	const struct Gdef *lg = l;
	const struct Gdef *rg = r;
	int c;

	if ((c = strcmp(lg->g_id, rg->g_id)) < 1) {
		return (-1);
	} else if (c > 1) {
		return (1);
	} else {
		return (0);
	}
}

static void
ttydefs_line(uint_t lnum, const char *line)
{
	struct Gdef *g = alloc_def();

	/*
	 * We read one colon-separated field at a time.
	 */
	bool failed = false;
	ttydefs_field_t f = T_TTYLABEL;
	const char *ptr = line;
	char *t;
	while (!failed) {
		size_t size;

		switch (f) {
		case T_TTYLABEL:
			g->g_id = getword(ptr, &size, false);
			if (size < 1) {
				failed = true;
			}
			break;

		case T_IFLAGS:
			g->g_iflags = getword(ptr, &size, true);
			if (check_flags(g->g_iflags) != 0) {
				failed = true;
			}
			break;

		case T_FFLAGS:
			g->g_fflags = getword(ptr, &size, true);
			if (check_flags(g->g_fflags) != 0) {
				failed = true;
			}
			break;

		case T_AUTOBAUD:
			t = getword(ptr, &size, false);
			if (strcmp(t, "A") == 0) {
				g->g_autobaud |= A_FLAG;
			} else if (strcmp(t, "") != 0) {
				failed = true;
			}
			free(t);
			break;

		case T_NEXTLABEL:
			g->g_nextid = getword(ptr, &size, false);
			break;

		default:
			abort();
		}

		if (failed) {
			break;
		}

		ptr += size;

		if (f == T_NEXTLABEL) {
			if (*ptr == '\0') {
				/*
				 * Processing is complete.
				 */
				break;
			} else {
				/*
				 * This was meant to be the last field.
				 */
				failed = true;
				break;
			}

		} else if (*ptr == ':') {
			/*
			 * Skip the colon and advance to the next field.  Note
			 * that this works because the enum variants are
			 * arranged in ascending order.
			 */
			ptr++;
			f++;
			continue;

		} else {
			failed = true;
			break;
		}
	}

	if (!failed) {
		g->g_line = safe_strdup(line);
		insert_def(g);
	} else {
		free_def(g);
		log("Parsing failure in the \"%s\" field of line %u: \"%s\"",
		    ttydefs_field_name(f), lnum, line);
	}
}

/*
 * read_ttydefs	- read in the /etc/ttydefs and store in Gdef tree
 */
void
read_ttydefs(void)
{
	if (g_defs_init) {
		/*
		 * We have already read the file once, and are being asked to
		 * discard the prior version and reread.
		 */
		void *cookie = NULL;
		struct Gdef *g;

		while ((g = avl_destroy_nodes(&g_defs, &cookie)) != NULL) {
			g->g_next = NULL;
			free_def(g);
		}

		avl_destroy(&g_defs);
		g_defs_init = false;
		g_defs_head = NULL;
		g_defs_tail = NULL;
	}

	g_defs_init = true;
	avl_create(&g_defs, g_defs_compare, sizeof (struct Gdef),
	    offsetof(struct Gdef, g_node));

	(void) walk_table(TTYDEFS, ttydefs_line, &g_ttydefs_mtime);
}

/*
 * find_def(ttylabel)
 *	- scan Gdef table for an entry with requested "ttylabel".
 *	- return a Gdef ptr if entry with "ttylabel" is found 
 *	- return NULL if no entry with matching "ttylabel"
 */
const struct Gdef *
find_def(const char *ttylabel)
{
	if (!g_defs_init) {
		return (NULL);
	}

	struct Gdef g = { .g_id = (char *)ttylabel };

	return (avl_find(&g_defs, &g, NULL));
}

/*
 * check_flags	- check to see if the flags contains options that are
 *		  recognizable by stty
 *		- return 0 if no error. Otherwise return -1
 */
int
check_flags(const char *flags)
{
	struct termio termio;
	struct termios termios;
	struct termiox termiox;
	struct winsize winsize;
	int term;
	int r = 0;
	char *s_arg;		/* this will point to invalid option */
	strlist_t *args = NULL;

	/*
	 * Create a fake argument list for stty:
	 */
	if (strlist_alloc(&args, 8) != 0 ||
	    strlist_set(args, 0, "/usr/bin/stty") != 0) {
		log("could not allocate argument memory: %s", strerror(errno));
		strlist_free(args);
		return (-1);
	}
	mkargv(flags, args);

	/*
	 * because we don't know what type of terminal we have now,
	 * just set term = everything, so all possible stty options
	 * are accepted
	 */
	term = ASYNC|TERMIOS|FLOW;
	if ((s_arg = sttyparse(strlist_contig_count(args),
	    strlist_array(args), term, &termio, &termios,
	    &termiox, &winsize)) != NULL) {
		log("invalid mode: %s", s_arg);
		r = -1;
	}

	strlist_free(args);
	return (r);
}

/*
 * insert_def - insert one entry into Gdef table
 */
static void
insert_def(struct Gdef *g)
{
	avl_index_t where;

	printf("CHECK %s\n", g->g_id);
	print_ttydef(g);

	if (avl_find(&g_defs, g, &where) != NULL) {
		log("Warning -- duplicate entry <%s>, ignored", g->g_id);
		free_def(g);
		return;
	}

	printf("INSERT %s\n", g->g_id);
	avl_insert(&g_defs, g, where);

	/*
	 * Maintain a linked list of the order in which lines appeared in the
	 * file for printing during the check phase.
	 */
	if (g_defs_tail != NULL) {
		g_defs_tail->g_next = g;
	}
	g_defs_tail = g;
}

static void
free_def(struct Gdef *g)
{
	VERIFY3P(g->g_next, ==, NULL);
	free(g->g_id);
	free(g->g_iflags);
	free(g->g_fflags);
	free(g->g_nextid);
	free(g);
}

static struct Gdef *
alloc_def(void)
{
	struct Gdef *g;

	if ((g = calloc(1, sizeof (*g))) == NULL) {
		log("could not allocate memory for ttydefs table");
		exit(1);
	}

	return (g);
}

const struct Gdef *
next_def(const struct Gdef *g)
{
	if (g == NULL) {
		return (g_defs_head);
	}

	return (g->g_next);
}

/*
 * mkargv - parse the string into args, starting from args[cnt]
 */
void
mkargv(const char *string, strlist_t *args)
{
	ilstr_t ils;

	ilstr_init(&ils, 0);

	enum {
		ST_REST = 1,
		ST_ARG
	} state = ST_REST;

	for (;;) {
		char c = *string;

		switch (state) {
		case ST_REST:
			if (c == '\0') {
				goto done;
			}
			if (c == ' ' || c == '\t') {
				/*
				 * Skip excess whitespace between arguments.
				 */
				string++;
				continue;
			}
			ilstr_reset(&ils);
			state = ST_ARG;
			continue;

		case ST_ARG:
			if (c == '\0' || c == ' ' || c == '\t') {
				/*
				 * Attempt to commit the argument we've read.
				 */
				if (ilstr_errno(&ils) != 0) {
					log("error processing arguments: %s",
					    ilstr_errstr(&ils));
					exit(1);
				}
				if (strlist_set_tail(args,
				    ilstr_cstr(&ils)) != 0) {
					log("error appending arguments: %s",
					    strerror(errno));
					exit(1);
				}
				if (c == '\0') {
					goto done;
				}
				state = ST_REST;
				continue;
			}
			if (c == '\\') {
				size_t qsize;

				ilstr_append_char(&ils,
				    quoted(string, &qsize));
				string += qsize;
				continue;
			}
			ilstr_append_char(&ils, c);
			string++;
			continue;
		}
	}

done:
	ilstr_fini(&ils);
}

#ifdef	DEBUG
/*
 * dump_ttydefs - dump Gdef table to log file
 */
void
dump_ttydefs()
{
	log("********** dumping ttydefs table **********");
	log("Ndefs = %d", avl_numnodes(&g_defs));
	log(" ");

	for (struct Gdef *g = g_defs_head; g != NULL; g = g->g_next) {
		log("----------------------------------------");
		log("ttylabel:\t%s", g->g_id);
		log("initial flags:\t%s", g->g_iflags);
		log("final flags:\t%s", g->g_fflags);
		if (g->g_autobaud & A_FLAG) 
			log("autobaud:\tyes");
		else
			log("autobaud:\tno");
		log("nextlabel:\t%s", g->g_nextid);
		log(" ");
	}

	log("********** end dumping ttydefs table **********");
}
#endif
