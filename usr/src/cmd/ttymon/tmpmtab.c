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


#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/avl.h>
#include <sys/debug.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include "ttymon.h"
#include "tmstruct.h"
#include "tmextern.h"

static bool g_pmtab_init = false;
static avl_tree_t g_pmtab;

void	purge();
static int get_flags(const char *, long *);
static int get_ttyflags(const char *, long *);
static	int	same_entry();
static	int	check_pmtab();
static	void	insert_pmtab();
static	void	free_pmtab();
static	char	*expand(const char *, const char *);

static int check_identity();


typedef enum {
	P_TAG = 1,
	P_FLAGS,
	P_IDENTITY,
	P_RES1,
	P_RES2,
	P_RES3,
	P_DEVICE,
	P_TTYFLAGS,
	P_COUNT,
	P_SERVER,
	P_TIMEOUT,
	P_TTYLABEL,
	P_MODULES,
	P_PROMPT,
	P_DMSG,
	P_TERMTYPE,
	P_SOFTCAR
} pmtab_field_t;

const char *
pmtab_field_name(pmtab_field_t f)
{
	switch (f) {
	case P_TAG:
		return ("tag");
	case P_FLAGS:
		return ("flags");
	case P_IDENTITY:
		return ("identity");
	case P_RES1:
		return ("reserved1");
	case P_RES2:
		return ("reserved2");
	case P_RES3:
		return ("reserved3");
	case P_DEVICE:
		return ("device");
	case P_TTYFLAGS:
		return ("ttyflags");
	case P_COUNT:
		return ("count");
	case P_SERVER:
		return ("service");
	case P_TIMEOUT:
		return ("timeout");
	case P_TTYLABEL:
		return ("ttylabel");
	case P_MODULES:
		return ("modules");
	case P_PROMPT:
		return ("prompt");
	case P_DMSG:
		return ("disable message");
	case P_TERMTYPE:
		return ("terminal type");
	case P_SOFTCAR:
		return ("soft-carrier");
	}

	abort();
}

static void
pmtab_line(uint_t linenum, const char *line)
{
#ifdef DEBUG
	debug("**** Next Entry ****\n%s", line);
#endif
	log("Processing pmtab line #%d", linenum);

	struct pmtab *pmt;
	if ((pmt = calloc(1, sizeof (*pmt))) == NULL) {
		fatal("memory allocation failed");
	}

	/*
	 * Set hangup flag.  This is the default.
	 */
	pmt->pmt_ttyflags |= H_FLAG;

	bool failed = false;
	pmtab_field_t f = P_TAG;
	size_t size;
	const char *ptr = line;
	char *t;
	while (!failed) {
		switch (f) {
		case P_TAG:
			pmt->pmt_tag = getword(ptr, &size, false);
			break;

		case P_FLAGS:
			t = getword(ptr, &size, false);
			if (get_flags(t, &pmt->pmt_flags) != 0) {
				failed = true;
			}
			free(t);
			break;

		case P_IDENTITY:
			pmt->pmt_identity = getword(ptr, &size, false);
			break;

		case P_RES1:
			pmt->pmt_res1 = getword(ptr, &size, false);
			break;

		case P_RES2:
			pmt->pmt_res2 = getword(ptr, &size, false);
			break;

		case P_RES3:
			pmt->pmt_res3 = getword(ptr, &size, false);
			break;

		case P_DEVICE:
			pmt->pmt_device = getword(ptr, &size, false);
			break;

		case P_TTYFLAGS:
			t = getword(ptr, &size, false);
			if (get_ttyflags(t, &pmt->pmt_ttyflags) != 0) {
				failed = true;
			}
			free(t);
			break;

		case P_COUNT:
			t = getword(ptr, &size, false);
			if (strcheck(t, NUM) != 0) {
				log("wait_read count must be a "
				    "positive number"); 
				failed = true;
			} else {
				pmt->pmt_count = atoi(t);
			}
			free(t);
			break;

		case P_SERVER:
			t = getword(ptr, &size, true);
			pmt->pmt_server = expand(t, pmt->pmt_device);
			free(t);
			break;

		case P_TIMEOUT:
			t = getword(ptr, &size, false);
			if (strcheck(t, NUM) != 0) {
				log("timeout value must be a "
				    "positive number"); 
				failed = true;
			} else {
				pmt->pmt_timeout = atoi(t);
			}
			free(t);
			break;

		case P_TTYLABEL:
			pmt->pmt_ttylabel = getword(ptr, &size, false);
			break;

		case P_MODULES:
			pmt->pmt_modules = getword(ptr, &size, false);
			if (vml(pmt->pmt_modules) != 0) {
				failed = true;
			}
			break;

		case P_PROMPT:
			pmt->pmt_prompt = getword(ptr, &size, true);
			break;

		case P_DMSG:
			pmt->pmt_dmsg = getword(ptr, &size, true);
			break;

		case P_TERMTYPE:
			pmt->pmt_termtype = getword(ptr, &size, true);
			break;

		case P_SOFTCAR:
			pmt->pmt_softcar = getword(ptr, &size, true);
			break;

		default:
			abort();
		}

		if (failed) {
			break;
		}

		ptr += size;

		if (f > P_DMSG && *ptr == '\0') {
			/*
			 * Solaris treated several of the final fields as
			 * optional, for compatibility with what must now be
			 * truly ancient software.  Because this was done by
			 * ignoring empty fields rather than by correctly
			 * versioning the file, we have no real way to know if
			 * our software has been correctly including the new
			 * fields at all times.  As such, we continue to ignore
			 * empty values here just in case.
			 */
			if (pmt->pmt_termtype == NULL) {
				pmt->pmt_termtype = safe_strdup("");
			}
			if (pmt->pmt_softcar == NULL) {
				pmt->pmt_softcar = safe_strdup("");
			}
			break;

		} else if (f == P_SOFTCAR) {
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
		if (check_pmtab(pmt) == 0) {
			insert_pmtab(pmt);
		} else {
			log("Parsing failure for line %u: \"%s\"",
			    linenum, line);
			log("-------------------------------------------");
			free_pmtab(pmt);
		}
	} else {
		log("Parsing failure in the \"%s\" field of line %u: \"%s\"",
		    pmtab_field_name(f), linenum, line);
		log("-------------------------------------------");
		free_pmtab(pmt);
	}
}

static int
g_pmtab_compare(const void *l, const void *r)
{
	const struct pmtab *lpmt = l;
	const struct pmtab *rpmt = r;
	int c;

	if ((c = strcmp(lpmt->pmt_tag, rpmt->pmt_tag)) < 0) {
		return (-1);
	} else if (c > 0) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * read_pmtab() 
 *	- read and parse pmtab 
 *	- store table in linked list pointed by global variable "PMtab"
 *	- exit if file does not exist or error detected.
 */
void
read_pmtab(void)
{
#ifdef DEBUG
	debug("in read_pmtab");
#endif

	if (check_version(PMTAB_VERS, PMTABFILE) != 0)
		fatal("check pmtab version failed");

	if (!g_pmtab_init) {
		avl_create(&g_pmtab, g_pmtab_compare, sizeof (struct pmtab),
		    offsetof(struct pmtab, pmt_node));
		g_pmtab_init = true;
	}

	/*
	 * Walk through any existing pmtab entries and invalidate them.  This
	 * enables us to know which entries are no longer in the file and
	 * should be retired.
	 */
	for (struct pmtab *pmt = avl_first(&g_pmtab); pmt != NULL;
	    pmt = AVL_NEXT(&g_pmtab, pmt)) {
		if (pmt->pmt_status == SESSION ||
		    pmt->pmt_status == LOCKED ||
		    pmt->pmt_status == UNACCESS) {
			if (pmt->pmt_fd > 0) {
				safe_close(pmt->pmt_fd);
				pmt->pmt_fd = 0;
			}
			pmt->pmt_inservice = pmt->pmt_status;
		}
		pmt->pmt_status = NOTVALID;
	}

	(void) walk_table(PMTABFILE, pmtab_line, NULL);
}

/*
 * get_flags - scan flags field to set U_FLAG and X_FLAG
 */
static int
get_flags(const char *wptr, long *flags)
{
	for (const char *p = wptr; *p; p++) {
		switch (*p) {
		case 'x':
			*flags |= X_FLAG;
			break;
		case 'u':
			*flags |= U_FLAG;
			break;
		default:
			log("Invalid flag -- %c", *p);
			return (-1);
		} 
	}

	return (0);
}

/*
 * get_ttyflags	- scan ttyflags field to set corresponding flags
 */
static int
get_ttyflags(const char *wptr, long *ttyflags)
{
	for (const char *p = wptr; *p; p++) {
		switch (*p) {
		case 'c':
			*ttyflags |= C_FLAG;
			break;
		case 'h': /* h means don't hangup */
			*ttyflags &= ~H_FLAG;
			break;
		case 'b':
			*ttyflags |= B_FLAG;
			break;
		case 'r':
			*ttyflags |= R_FLAG;
			break;
		case 'I':
			*ttyflags |= I_FLAG;
			break;
		default:
			log("Invalid ttyflag -- %c", *p);
			return (-1);
		} 
	}

	return (0);
}

# ifdef DEBUG
/*
 * pflags - put service flags into intelligible form for output
 */

char *
pflags(flags)
long flags;	/* binary representation of the flags */
{
	register int i;			/* scratch counter */
	static char buf[BUFSIZ];	/* formatted flags */

	if (flags == 0)
		return ("-");
	i = 0;
	if (flags & U_FLAG) {
		buf[i++] = 'u';
		flags &= ~U_FLAG;
	}
	if (flags & X_FLAG) {
		buf[i++] = 'x';
		flags &= ~X_FLAG;
	}
	if (flags)
		log("Internal error in pflags");
	buf[i] = '\0';
	return (buf);
}

/*
 * pttyflags - put ttyflags into intelligible form for output
 */

char *
pttyflags(flags)
long flags;	/* binary representation of ttyflags */
{
	register int i;			/* scratch counter */
	static char buf[BUFSIZ];	/* formatted flags */

	if (flags == 0)
		return ("h");
	i = 0;
	if (flags & C_FLAG) {
		buf[i++] = 'c';
		flags &= ~C_FLAG;
	}
	if (flags & H_FLAG) 
		flags &= ~H_FLAG;
	else
		buf[i++] = 'h';
	if (flags & B_FLAG) {
		buf[i++] = 'b';
		flags &= ~B_FLAG;
	}
	if (flags & R_FLAG) {
		buf[i++] = 'r';
		flags &= ~B_FLAG;
	}
	if (flags & I_FLAG) {
		buf[i++] = 'I';
		flags &= ~I_FLAG;
	}
	if (flags)
		log("Internal error in pmt_ttyflags");
	buf[i] = '\0';
	return (buf);
}

void
dump_pmtab()
{
	struct	pmtab *gptr;

	debug("in dump_pmtab");
	log("********** dumping pmtab **********");
	log(" ");
	for (gptr=PMtab; gptr; gptr = gptr->pmt_next) {
		log("-------------------------------------------");
		log("tag:\t\t%s", gptr->pmt_tag);
		log("flags:\t\t%s",pflags(gptr->pmt_flags));
		log("identity:\t%s", gptr->pmt_identity);
		log("reserved1:\t%s", gptr->pmt_res1);
		log("reserved2:\t%s", gptr->pmt_res2);
		log("reserved3:\t%s", gptr->pmt_res3);
		log("device:\t%s", gptr->pmt_device);
		log("ttyflags:\t%s",pttyflags(gptr->pmt_ttyflags));
		log("count:\t\t%d", gptr->pmt_count);
		log("server:\t%s", gptr->pmt_server);
		log("timeout:\t%d", gptr->pmt_timeout);
		log("ttylabel:\t%s", gptr->pmt_ttylabel);
		log("modules:\t%s", gptr->pmt_modules);
		log("prompt:\t%s", gptr->pmt_prompt);
		log("disable msg:\t%s", gptr->pmt_dmsg);
		log("terminal type:\t%s", gptr->pmt_termtype);
		log("soft-carrier:\t%s", gptr->pmt_softcar);
		log("status:\t\t%d", gptr->pmt_status);
		log("inservice:\t%d", gptr->pmt_inservice);
		log("fd:\t\t%d", gptr->pmt_fd);
		log("pid:\t\t%ld", gptr->pmt_pid);
		log("uid:\t\t%ld", gptr->pmt_uid);
		log("gid:\t\t%ld", gptr->pmt_gid);
		log("dir:\t%s", gptr->pmt_dir);
		log(" ");
	}
	log("********** end dumping pmtab **********");
}
# endif

/*
 * same_entry(e1,e2) -    compare 2 entries of pmtab
 *			if the fields are different, copy e2 to e1
 * 			return 1 if same, return 0 if different
 */
static int
same_entry(struct pmtab *e1, struct pmtab *e2)
{

	if (strcmp(e1->pmt_identity, e2->pmt_identity) != 0)
		return (0);
	if (strcmp(e1->pmt_res1, e2->pmt_res1) != 0)
		return (0);
	if (strcmp(e1->pmt_res2, e2->pmt_res2) != 0)
		return (0);
	if (strcmp(e1->pmt_res3, e2->pmt_res3) != 0)
		return (0);
	if (strcmp(e1->pmt_device, e2->pmt_device) != 0)
		return (0);
	if (strcmp(e1->pmt_server, e2->pmt_server) != 0)
		return (0);
	if (strcmp(e1->pmt_ttylabel, e2->pmt_ttylabel) != 0)
		return (0);
	if (strcmp(e1->pmt_modules, e2->pmt_modules) != 0)
		return (0);
	if (strcmp(e1->pmt_prompt, e2->pmt_prompt) != 0)
		return (0);
	if (strcmp(e1->pmt_dmsg, e2->pmt_dmsg) != 0)
		return (0);
	if (strcmp(e1->pmt_termtype, e2->pmt_termtype) != 0)
		return (0);
	if (strcmp(e1->pmt_softcar, e2->pmt_softcar) != 0)
		return (0);
	if (e1->pmt_flags != e2->pmt_flags)
		return (0);
	/*
	 * compare lowest 4 bits only, 
	 * because A_FLAG is not part of original ttyflags
	 */
	if ((e1->pmt_ttyflags & ~A_FLAG) != (e2->pmt_ttyflags & ~A_FLAG))
		return (0);
	if (e1->pmt_count != e2->pmt_count)
		return (0);
	if (e1->pmt_timeout != e2->pmt_timeout)
		return (0);
	if (e1->pmt_uid != e2->pmt_uid)
		return (0);
	if (e1->pmt_gid != e2->pmt_gid)
		return (0);
	if (strcmp(e1->pmt_dir, e2->pmt_dir) != 0)
		return (0);
	return (1);
}


/*
 * insert_pmtab - insert a pmtab entry into the linked list
 */
static void
insert_pmtab(struct pmtab *sp)
{
#ifdef DEBUG
	debug("in insert_pmtab");
#endif

	struct pmtab *tsp;
	avl_index_t where;

	if ((tsp = avl_find(&g_pmtab, sp, &where)) != NULL) {
		/*
		 * There is an existing pmtab entry with a matching tag.  We
		 * need to reconfigure it to match the new entry.
		 */
		if (tsp->pmt_status != NOTVALID) {
			/*
			 * We have already seen and processed an entry with the
			 * same tag earlier in this cycle.  This must be a
			 * duplicate.
			 */
			log("Ignoring duplicate entry for <%s>",
			    tsp->pmt_tag);
			free_pmtab(sp);
			return;
		}

		if (same_entry(tsp, sp)) {
			/*
			 * The configuration for this entry is identical to
			 * that of the existing entry.  Mark it valid so that
			 * it is not purged.
			 */
			tsp->pmt_status = VALID;
			free_pmtab(sp);
			return;
		}

		if ((sp->pmt_flags & X_FLAG) && empty(sp->pmt_dmsg)) {
			/*
			 * This entry is now disabled via the 'x' flag, and is
			 * not configured with a disabled response message to
			 * deliver.  We need to stop polling.
			 */
			tsp->pmt_status = NOTVALID;
			free_pmtab(sp);
			return;
		}

#ifdef DEBUG
		debug("replacing <%s>", sp->pmt_tag);
#endif

		/*
		 * Preserve any dynamic state from the old entry and mark it as
		 * changed, rather than new:
		 */
		sp->pmt_status = CHANGED;
		sp->pmt_fd = tsp->pmt_fd;
		sp->pmt_pid = tsp->pmt_pid;
		sp->pmt_inservice = tsp->pmt_inservice;

		/*
		 * Remove and free the original and get a new AVL insertion
		 * index:
		 */
		avl_remove(&g_pmtab, tsp);
		free_pmtab(tsp);
		VERIFY3P(avl_find(&g_pmtab, sp, &where), ==, NULL);

	} else {
		/*
		 * This pmtab entry appears to be active and wholly new, so we
		 * need to add it to the table.
		 */
		sp->pmt_status = VALID;
	}

	if ((sp->pmt_flags & X_FLAG) && empty(sp->pmt_dmsg)) {
		/*
		 * This entry is disabled via the 'x' flag, and is not
		 * configured with a disabled response message to deliver.  We
		 * do not need to poll this entry.
		 */
		free_pmtab(sp);
		return;
	}

	/*
	 * Set the state of soft-carrier.  Since this is a one-time only
	 * operation, we do it when this service is added to the enabled list.
	 */
	if (*sp->pmt_softcar != '\0') {
		set_softcar(sp);
	}

# ifdef DEBUG
	debug("adding <%s>", sp->pmt_tag);
# endif
	avl_insert(&g_pmtab, sp, where);
}

/*
 * purge - purge linked list of "old" entries
 */
void
purge(void)
{
# ifdef DEBUG
	debug("in purge");
# endif

	struct pmtab *save;
	for (struct pmtab *pmt = avl_first(&g_pmtab); pmt != NULL;
	    pmt = save) {
		/*
		 * Always save the next item in the tree so that we can safely
		 * remove the current one.
		 */
		save = AVL_NEXT(&g_pmtab, pmt);

		if (pmt->pmt_status != 0) {
# ifdef DEBUG
			debug("pmt_status not 0");
# endif
		} else {
# ifdef DEBUG
			debug("purging <%s>", pmt->pmt_tag);
# endif

			avl_remove(&g_pmtab, pmt);
			free_pmtab(pmt);
		}
	}
}

struct pmtab *
next_pmtab(struct pmtab *pmt)
{
	if (pmt == NULL) {
		return (avl_first(&g_pmtab));
	} else {
		return (AVL_NEXT(&g_pmtab, pmt));
	}
}

/*
 *	free_pmtab	- free one pmtab entry
 */
static void
free_pmtab(struct pmtab *p)
{
#ifdef	DEBUG
	debug("in free_pmtab");
#endif
	free(p->pmt_tag);
	free(p->pmt_identity);
	free(p->pmt_res1);
	free(p->pmt_res2);
	free(p->pmt_res3);
	free(p->pmt_device);
	free(p->pmt_server);
	free(p->pmt_ttylabel);
	free(p->pmt_modules);
	free(p->pmt_prompt);
	free(p->pmt_dmsg);
	free(p->pmt_termtype);
	free(p->pmt_softcar);
	free(p->pmt_dir);
	free(p);
}

/*
 *	check_pmtab - check the fields to make sure things are correct
 *		    - return 0 if everything is ok
 *		    - return -1 if something is wrong
 */
static int
check_pmtab(struct pmtab *p)
{
	if (p == NULL) {
		log("pmtab ptr is NULL");
		return (-1);
	}

	/* check service tag */
	if (empty(p->pmt_tag)) {
		log("port/service tag is missing");
		return (-1);
	}
	if (strlen(p->pmt_tag) > (size_t)(MAXID - 1)) {
		log("port/service tag <%s> is longer than %d", p->pmt_tag,
		    MAXID-1);
		return (-1);
	}
	if (strcheck(p->pmt_tag, ALNUM) != 0) {
		log("port/service tag <%s> is not alphanumeric", p->pmt_tag);
		return (-1);
	}
	if (check_identity(p) != 0) {
		return (-1);
	}

	if (check_device(p->pmt_device) != 0)
		return (-1);

	if (check_cmd(p->pmt_server) != 0)
		return (-1);

	return (0);
}

/*
 *	check_identity - check to see if the identity is a valid user
 *		       - log name in the passwd file,
 *		       - and if its group id is a valid one
 *		  	- return 0 if everything is ok. Otherwise, return -1
 */
static int
check_identity(struct pmtab *p)
{
	register struct passwd *pwdp;

	if (empty(p->pmt_identity)) {
		log("identity field is missing");
		return (-1);
	}
	if ((pwdp = getpwnam(p->pmt_identity)) == NULL) {
		log("missing or bad passwd entry for <%s>", p->pmt_identity);
		endpwent();
		return (-1);
	}
	if (getgrgid(pwdp->pw_gid) == NULL) {
		log("no group entry for %ld", pwdp->pw_gid);
		endgrent();
		endpwent();
		return (-1);
	}
	p->pmt_uid = pwdp->pw_uid;
	p->pmt_gid = pwdp->pw_gid;
	p->pmt_dir = safe_strdup(pwdp->pw_dir);
	endgrent();
	endpwent();
	return (0);
}

/*
 * expand(cmdp, devp)	- expand %d to device name and %% to %,
 *				- any other characters are untouched.
 *				- return the expanded string
 */
static char *
expand(const char *cmdp, const char *devp)
{
	const char *cp = cmdp, *dp = devp;
	char buf[BUFSIZ];
	char *np = buf;

	while (*cp != '\0') {
		if (*cp != '%') {
			*np++ = *cp++;
			continue;
		}

		switch (*++cp) {
		case 'd':
			while (*dp != '\0') {
				*np++ = *dp++;
			}
			cp++;
			break;
		case '%':
			*np++ = *cp++;
			break;
		default:
			*np++ = *cp++;
			break;
		}
	}
	*np = '\0';

	return (safe_strdup(buf));
}
