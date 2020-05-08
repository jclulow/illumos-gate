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
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include "ttymon.h"
#include "tmstruct.h"
#include "tmextern.h"

void	purge();
static	int	get_flags();
static	int	get_ttyflags();
static	int	same_entry();
static	int	check_pmtab();
static	void	insert_pmtab();
static	void	free_pmtab();
static	char	*expand(const char *, const char *);

static int check_identity();

/*
 * read_pmtab() 
 *	- read and parse pmtab 
 *	- store table in linked list pointed by global variable "PMtab"
 *	- exit if file does not exist or error detected.
 */
void
read_pmtab()
{
	struct pmtab *gptr;
	char *ptr, *wptr;
	FILE 	 *fp;
	int 	 input, state, size, rawc, field, linenum;
	char 	 oldc;
	char 	 line[BUFSIZ];
	char 	 wbuf[BUFSIZ];
	static 	 char *states[] = { P_STATE_LIST };

#ifdef DEBUG
	debug("in read_pmtab");
#endif

	if ((fp = fopen(PMTABFILE,"r")) == NULL) {
		fatal("open pmtab (%s) failed", PMTABFILE);
	}

	Nentries = 0;
	if (check_version(PMTAB_VERS, PMTABFILE) != 0)
		fatal("check pmtab version failed");

	for (gptr = PMtab; gptr; gptr = gptr->pmt_next) {
		if (gptr->pmt_status == SESSION ||
		    gptr->pmt_status == LOCKED ||
		    gptr->pmt_status == UNACCESS) {
			if (gptr->pmt_fd > 0) {
				safe_close(gptr->pmt_fd);
				gptr->pmt_fd = 0;
			}
			gptr->pmt_inservice = gptr->pmt_status;
		}
		gptr->pmt_status = NOTVALID;
	}

	wptr = wbuf;
	input = ACTIVE;
	linenum = 0;
	do {
		linenum++;
		line[0] = '\0';
		for (ptr = line, oldc = '\0';
		    (rawc = getc(fp)) != '\n' && rawc != EOF &&
		    ptr < &line[sizeof (line) - 1];
		    ptr++, oldc = (char)rawc) {
			if (rawc == '#' && oldc != '\\') {
				break;
			}
			*ptr = (char)rawc;
		}
		*ptr = '\0';

		/* skip rest of the line */
		if (rawc != EOF && rawc != '\n') {
			if (rawc != '#') 
				log("Entry too long.\n");
			while ((rawc = getc(fp)) != EOF && rawc != '\n') 
				;
		}

		if (rawc == EOF) {
			if (ptr == line)
				break;
			else
				input = FINISHED;
		}

		/* if empty line, skip */
		for (ptr = line; *ptr != '\0' && isspace(*ptr); ptr++)
			;
		if (*ptr == '\0')
			continue;

#ifdef DEBUG
		debug("**** Next Entry ****\n%s", line);
#endif
		log("Processing pmtab line #%d", linenum);

		/* Now we have the complete line */

		if ((gptr = calloc(1, sizeof (*gptr))) == NULL) {
			fatal("memory allocation failed");
		}

		/* set hangup flag, this is the default */
		gptr->pmt_ttyflags |= H_FLAG;

		/*
		 * For compatibility reasons, we cannot rely on these
		 * having values assigned from pmtab.
		 */
		gptr->pmt_termtype = "";
		gptr->pmt_softcar = "";

		state = P_TAG;
		field = state;
		ptr = line;
		while (state != FAILURE && state != SUCCESS) {
			switch (state) {
			case P_TAG:
				gptr->pmt_tag = safe_strdup(getword(ptr,
				    &size, 0));
				break;

			case P_FLAGS:
				(void) strcpy(wptr, getword(ptr, &size, 0));
				if (get_flags(wptr, &gptr->pmt_flags) != 0) {
					field = state;
					state = FAILURE;
				}
				break;

			case P_IDENTITY:
				gptr->pmt_identity = safe_strdup(getword(ptr,
				    &size, 0));
				break;

			case P_RES1:
				gptr->pmt_res1 = safe_strdup(getword(ptr, &size,
				    0));
				break;

			case P_RES2:
				gptr->pmt_res2 = safe_strdup(getword(ptr, &size,
				    0));
				break;

			case P_RES3:
				gptr->pmt_res3 = safe_strdup(getword(ptr, &size,
				    0));
				break;

			case P_DEVICE:
				gptr->pmt_device = safe_strdup(getword(ptr, &size,
				    0));
				break;

			case P_TTYFLAGS:
				(void) strcpy(wptr, getword(ptr, &size, 0));
				if (get_ttyflags(wptr, &gptr->pmt_ttyflags) !=
				    0) {
					field = state;
					state = FAILURE;
				}
				break;

			case P_COUNT:
				(void) strcpy(wptr, getword(ptr, &size, 0));
				if (strcheck(wptr, NUM) != 0) {
					log("wait_read count must be a "
					    "positive number"); 
					field = state;
					state = FAILURE;
				} else {
				    gptr->pmt_count = atoi(wptr);
				}
				break;

			case P_SERVER:
				gptr->pmt_server = expand(getword(ptr, size, 1),
				    gptr->pmt_device);
				break;

			case P_TIMEOUT:
				(void) strcpy(wptr, getword(ptr, &size, 0));
				if (strcheck(wptr, NUM) != 0) {
					log("timeout value must be a "
					    "positive number"); 
					field = state;
					state = FAILURE;
				} else {
				    gptr->pmt_timeout = atoi(wptr);
				}
				break;

			case P_TTYLABEL:
				gptr->pmt_ttylabel = safe_strdup(getword(ptr,
				    &size, 0));
				break;

			case P_MODULES:
				gptr->pmt_modules = safe_strdup(getword(ptr,
				    &size, 0));
				if (vml(gptr->pmt_modules) != 0) {
					field = state;
					state = FAILURE;
				}
				break;

			case P_PROMPT:
				gptr->pmt_prompt = safe_strdup(getword(ptr, &size,
				    TRUE));
				break;

			case P_DMSG:
				gptr->pmt_dmsg = safe_strdup(getword(ptr, &size,
				    TRUE));
				break;

			case P_TERMTYPE:
				gptr->pmt_termtype = safe_strdup(getword(ptr,
				    &size, TRUE));
				break;

			case P_SOFTCAR:
				gptr->pmt_softcar = safe_strdup(getword(ptr,
				    &size, TRUE));
				break;
			}

			ptr += size;
			if (state == FAILURE) 
				break;
			if (*ptr == ':') {
				ptr++;	/* Skip the ':' */
				state++;
			} else if (*ptr != '\0') {
				field = state;
				state = FAILURE;
			}

			if (*ptr == '\0') {
				/*
				 * Maintain compatibility with older ttymon
				 * pmtab files.  If Sun-added fields are
				 * missing, this should not be an error.
				 */
				if (state > P_DMSG) { 
					state = SUCCESS;
				} else {
					field = state;
					state = FAILURE;
				}
			}
		}

		if (state == SUCCESS) {
			if (check_pmtab(gptr) == 0) {
				if (Nentries < Maxfds) {
					insert_pmtab(gptr);
				} else {
					log("can't add more entries to "
					    "pmtab, Maxfds = %d", Maxfds);
					free_pmtab(gptr);
					(void) fclose(fp);
					return;
				}
			} else {
				log("Parsing failure for entry: \n%s", line);
				log("--------------------------------------"
				    "-----");
				free_pmtab(gptr);
			}
		} else {
			*++ptr = '\0';
			log("Parsing failure in the \"%s\" field,\n%s"
			    "<--error detected here", states[field], line);
			log("-------------------------------------------");
			free_pmtab(gptr);
		}
	} while (input == ACTIVE);

	(void)fclose(fp);
	return;
}

/*
 * get_flags	- scan flags field to set U_FLAG and X_FLAG
 */
static	int
get_flags(wptr, flags)
char	*wptr;		/* pointer to the input string	*/
long *flags;		/* pointer to the flag to set	*/
{
	register char	*p;
	for (p = wptr; *p; p++) {
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
static	int
get_ttyflags(wptr, ttyflags)
char	*wptr;		/* pointer to the input string	*/
long 	*ttyflags;	/* pointer to the flag to be set*/
{
	register char	*p;
	for (p = wptr; *p; p++) {
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
	struct pmtab *tsp, *savtsp;	/* scratch pointers */

#ifdef DEBUG
	debug("in insert_pmtab");
#endif
	savtsp = tsp = PMtab;

	/*
	 * find the correct place to insert this element
	 */
	while (tsp != NULL) {
		int ret = strcmp(sp->pmt_tag, tsp->pmt_tag);
		if (ret > 0) {
			/* keep on looking */
			savtsp = tsp;
			tsp = tsp->pmt_next;
			continue;
		} else if (ret == 0) {
			if (tsp->pmt_status) {
				/* this is a duplicate entry, ignore it */
				log("Ignoring duplicate entry for <%s>",
				    tsp->pmt_tag);
			} else {
				if (same_entry(tsp,sp)) { /* same entry */
					tsp->pmt_status = VALID;
				} else { /* entry changed */
					if ((sp->pmt_flags & X_FLAG) && 
					    ((sp->pmt_dmsg == NULL) ||
					    (*(sp->pmt_dmsg) == '\0'))) {
						/* disabled entry */
						tsp->pmt_status = NOTVALID;
					} else {
#ifdef DEBUG
						debug("replacing <%s>",
						    sp->pmt_tag);
#endif
						/* replace old entry */
						sp->pmt_next = tsp->pmt_next;
						if (tsp == PMtab) {
							PMtab = sp;
						} else {
							savtsp->pmt_next = sp;
						}
						sp->pmt_status = CHANGED;
						sp->pmt_fd = tsp->pmt_fd;
						sp->pmt_pid = tsp->pmt_pid;
					        sp->pmt_inservice =
						    tsp->pmt_inservice;
						sp = tsp;
					}
				}
				Nentries++;
			}
			free_pmtab(sp);
			return;
		} else {
			if ((sp->pmt_flags & X_FLAG) && 
			    ((sp->pmt_dmsg == NULL) ||
			    (*(sp->pmt_dmsg) == '\0'))) { /* disabled entry */
				free_pmtab(sp);
				return;
			}
			/*
			 * Set the state of soft-carrier.
			 * Since this is a one-time only operation,
			 * we do it when this service is added to
			 * the enabled list.
			 */
			if (*sp->pmt_softcar != '\0')
				set_softcar(sp);

			/* insert it here */
			if (tsp == PMtab) {
				sp->pmt_next = PMtab;
				PMtab = sp;
			} else {
				sp->pmt_next = savtsp->pmt_next;
				savtsp->pmt_next = sp;
			}
#ifdef DEBUG
			debug("adding <%s>", sp->pmt_tag);
#endif
			Nentries++;
			/* this entry is "current" */
			sp->pmt_status = VALID;
			return;
		}
	}

	/*
	 * either an empty list or should put element at end of list
	 */

	if ((sp->pmt_flags & X_FLAG) && 
	    ((sp->pmt_dmsg == NULL) ||
	    (*(sp->pmt_dmsg) == '\0'))) { /* disabled entry */
		free_pmtab(sp);		 /* do not poll this entry */
		return;
	}

	/*
	 * Set the state of soft-carrier.  Since this is a one-time only
	 * operation, we do it when this service is added to the enabled list.
	 */
	if (*sp->pmt_softcar != '\0')
		set_softcar(sp);
	sp->pmt_next = NULL;
	if (PMtab == NULL)
		PMtab = sp;
	else
		savtsp->pmt_next = sp;
# ifdef DEBUG
	debug("adding <%s>", sp->pmt_tag);
# endif
	++Nentries;
	/* this entry is "current" */
	sp->pmt_status = VALID;
}


/*
 * purge - purge linked list of "old" entries
 */
void
purge(void)
{
	struct pmtab *sp;		/* working pointer */
	struct pmtab *savesp, *tsp;	/* scratch pointers */

# ifdef DEBUG
	debug("in purge");
# endif
	sp = savesp = PMtab;
	while (sp != NULL) {
		if (sp->pmt_status) {
# ifdef DEBUG
			debug("pmt_status not 0");
# endif
			savesp = sp;
			sp = sp->pmt_next;
		} else {
			tsp = sp;
			if (tsp == PMtab) {
				PMtab = sp->pmt_next;
				savesp = PMtab;
			} else {
				savesp->pmt_next = sp->pmt_next;
			}
# ifdef DEBUG
			debug("purging <%s>", sp->pmt_tag);
# endif
			sp = sp->pmt_next;
			free_pmtab(tsp);
		}
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
	if (p->pmt_dir)
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
