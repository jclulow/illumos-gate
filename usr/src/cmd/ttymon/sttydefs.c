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


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <termio.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdarg.h>

#include "tmstruct.h"
#include "tmextern.h"
#include "ttymon.h"

static	int  nflg = 0;		/* -n seen */
static	int  iflg = 0;		/* -i seen */
static	int  fflg = 0;		/* -f seen */
static	int  lflg = 0;		/* -l seen */

static	void	usage();
static void check_ref(void);
static	void	add_entry();
static	void	remove_entry();
static	int	copy_file();
static	int	verify();
static	FILE	*open_temp();

/*
 * sttydefs - add, remove or check entries in /etc/ttydefs
 */

int
main(int argc, char *argv[])
{
	int c;
	int errflg = 0;
	int aflg = 0;
	int bflg = 0;
	int ret;
	const char *argtmp;
	struct Gdef g;

	if (argc == 1)
		usage();

	while ((c = getopt(argc, argv, "a:n:i:f:br:l")) != -1) {
		switch (c) {
		case 'a':
			aflg = TRUE;
			g.g_id = optarg;
			break;
		case 'n':
			nflg = TRUE;
			g.g_nextid = optarg;
			break;
		case 'i':
			iflg = TRUE;
			g.g_iflags = optarg;
			break;
		case 'f':
			fflg = TRUE;
			g.g_fflags = optarg;
			break;
		case 'b':
			bflg = TRUE;
			g.g_autobaud |= A_FLAG;
			break;
		case 'r':
			if ((argc > 3) || (optind < argc))
				usage();
			remove_entry(optarg);
			break;
		case 'l':
			lflg = TRUE;
			if (argc > 3) 
				usage();
			if ((ret = check_version(TTYDEFS_VERS, TTYDEFS)) != 0) {
				if (ret != 2) {
					(void)fprintf(stderr, "%s version number is incorrect or missing.\n",TTYDEFS);
					exit(1);
				}
				(void)fprintf(stderr, "sttydefs: can't open %s.\n",TTYDEFS);
				exit(1);
			}
			if (argv[optind] == NULL) {
				read_ttydefs();
				(void) check_ttydefs(NULL);
				printf("\n");
				check_ref();
			} else {
				if (argc == 3) { /* -l ttylabel */
					if (verify(argv[optind], 0) != 0) {
						errflg++;
						break;
					}
					argtmp = argv[optind];
				} else { /* -lttylabel */
					argtmp = argv[optind] + 2;
				}

				read_ttydefs();
				if (!check_ttydefs(argtmp)) {
					(void)fprintf(stderr,
					    "ttylabel <%s> not found.\n",
					    argtmp);
					exit(1);
				}

				/*
				 * Because check_ttydefs() succeeded for this
				 * label, we can just fetch it:
				 */
				const struct Gdef *g = find_def(argtmp);
				if (find_def(g->g_nextid) == NULL) {
					(void)printf("\nWarning -- nextlabel "
					    "<%s> of <%s> does not reference "
					    "any existing ttylabel.\n",
					    g->g_nextid, argtmp);
				}
			}
			exit(0);
			break;
		case '?':
			errflg++;
			break;
		}
		if (errflg) 
			usage();
	}
	if (optind < argc) 
		usage();

	if (aflg) {
		add_entry(&g);
	}

	if ((iflg) || (fflg) || (bflg) || (nflg)) {
		usage();
	}

	return (0); 
}

/*
 *	verify	- to check if arg is valid
 *		- i.e. arg cannot start with '-' and
 *		  arg must not longer than maxarglen
 *		- return 0 if ok. Otherwise return -1
 */
static int
verify(char *arg, size_t maxarglen)
{
	if (*arg == '-') {
		(void) fprintf(stderr, "Invalid argument -- %s.\n", arg);
		return (-1);
	}

	if (maxarglen != 0 && strlen(arg) > maxarglen) {
		arg[maxarglen] = '\0';
		(void) fprintf(stderr, "string too long, truncated to %s.\n",
		    arg);
		return (-1);
	}

	return(0);
}

/*
 * usage - print out a usage message
 */
static void
usage()
{
	(void) fprintf(stderr, "Usage:\tsttydefs -a ttylabel [-n nextlabel] "
	    "[-i initial-flags]\n\t\t [-f final-flags] [-b]\n");
	(void) fprintf(stderr, "\tsttydefs -r ttylabel\n");
	(void) fprintf(stderr, "\tsttydefs -l [ttylabel]\n");
	exit(2);
}

/*
 * add_entry - add an entry to /etc/ttydefs
 */
static void
add_entry(struct Gdef *ttydef)
{
	FILE *fp;
	int errflg = 0;
	char tbuf[BUFSIZ], *tp;
	int add_version = FALSE;

	if (getuid() != 0) {
		(void) fprintf(stderr, "User not privileged for operation.\n");
		exit(1);
	}

	tp = tbuf;
	*tp = '\0';
	if ((fp = fopen(TTYDEFS, "r")) != NULL) {
		if (check_version(TTYDEFS_VERS, TTYDEFS) != 0) {
			(void) fprintf(stderr, 
			    "%s version number is incorrect or missing.\n",
			    TTYDEFS);
			exit(1);
		}
		if (find_label(fp, ttydef->g_id) != 0) {
			(void) fclose(fp);
			(void) fprintf(stderr,
			    "Invalid request -- ttylabel <%s> already "
			    "exists.\n", ttydef->g_id);
			exit(1);
		}
		(void)fclose(fp);
	} else {
		/*
		 * If the file does not yet exist, we need to add the version
		 * header.
		 */
		add_version = TRUE;
	}

	if ((fp = fopen(TTYDEFS, "a+")) == NULL) {
		(void) fprintf(stderr, "Could not open \"%s\": %s", TTYDEFS,
		    strerror(errno));
		exit(1);
	}

	if (add_version) {
		(void) fprintf(fp,"# VERSION=%d\n", TTYDEFS_VERS);
	}

	/* if optional fields are not provided, set to default */
	if (!iflg) {
		ttydef->g_iflags = DEFAULT.g_iflags;
	} else {
		if (check_flags(ttydef->g_iflags) != 0) {
			errflg++;
		}
	}
	if (!fflg) {
		ttydef->g_fflags = DEFAULT.g_fflags;
	} else {
		if (check_flags(ttydef->g_fflags) != 0) {
			errflg++;
		}
	}

	if (errflg) {
		exit(1);
	}

	if (!nflg) {
		ttydef->g_nextid = ttydef->g_id;
	}

	char *abaud = (ttydef->g_autobaud & A_FLAG) ? "A" : "";
	(void) fprintf(fp, "%s:%s:%s:%s:%s\n", ttydef->g_id,
	    ttydef->g_iflags, ttydef->g_fflags, abaud, ttydef->g_nextid);

	(void) fclose(fp);
	exit(0);
}

static void
remove_entry(const char *ttylabel)
{
	FILE *tfp;		/* file pointer for temp file */
	int line;		/* line number entry is on */
	FILE *fp;		/* scratch file pointer */
	const char *tname = "/etc/.ttydefs";

	if (getuid() != 0) {
		(void) fprintf(stderr, "User not privileged for operation.\n");
		exit(1);
	}

	fp = fopen(TTYDEFS, "r");
	if (fp == NULL) {
		(void) fprintf(stderr, "Could not open \"%s\": %s", TTYDEFS,
		    strerror(errno));
		exit(1);
	}

	if (check_version(TTYDEFS_VERS, TTYDEFS) != 0) {
		(void) fprintf(stderr, 
		    "%s version number is incorrect or missing.\n", TTYDEFS);
		exit(1);
	}

	if ((line = find_label(fp, ttylabel)) == 0) {
		(void) fprintf(stderr, 
		    "Invalid request, ttylabel <%s> does not exist.\n",
		    ttylabel);
		exit(1);
	}

	tfp = open_temp(tname);

	if (line != 1) {
		/*
		 * Copy the lines before the line to delete into the temporary
		 * file:
		 */
		if (copy_file(fp, tfp, 1, line - 1)) {
			(void) fprintf(stderr,"Error accessing temp file.\n");
			exit(1);
		}
	}

	/*
	 * Copy the lines after the line to delete into the temporary file:
	 */
	if (copy_file(fp, tfp, line + 1, -1)) {
		(void) fprintf(stderr,"Error accessing temp file.\n");
		exit(1);
	}

	(void) fclose(fp);

	if (fclose(tfp) == EOF) {
		(void) unlink(tname);
		(void) fprintf(stderr,"Error closing temp file.\n");
		exit(1);
	}

	if (rename(tname, TTYDEFS) != 0) {
		perror("Rename failed");
		(void) unlink(tname);
		exit(1);
	}

	exit(0);
}

/*
 * open_temp - open up a temp file
 *
 *	args:	tname - temp file name
 */

static	FILE *
open_temp(tname)
char *tname;
{
	FILE *fp;			/* fp associated with tname */
	struct sigaction sigact;	/* for signal handling */

	sigact.sa_flags = 0;
	sigact.sa_handler = SIG_IGN;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGHUP);
	(void) sigaddset(&sigact.sa_mask, SIGINT);
	(void) sigaddset(&sigact.sa_mask, SIGQUIT);
	(void) sigaction(SIGHUP, &sigact, NULL);
	(void) sigaction(SIGINT, &sigact, NULL);
	(void) sigaction(SIGQUIT, &sigact, NULL);
	(void)umask(0333);
	if (access(tname, 0) != -1) {
		(void)fprintf(stderr,"tempfile busy; try again later.\n");
		exit(1);
	}
	fp = fopen(tname, "w");
	if (fp == NULL) {
		perror("Cannot create tempfile");
		exit(1);
	}
	return(fp);
}

/*
 * copy_file - copy information from one file to another, return 0 on
 *	success, -1 on failure
 *
 *	args:	fp - source file's file pointer
 *		tfp - destination file's file pointer
 *		start - starting line number
 *		finish - ending line number (-1 indicates entire file)
 */
static int
copy_file(FILE *fp, FILE *tfp, int start, int finish)
{
	int i;		/* loop variable */
	char dummy[BUFSIZ];	/* scratch buffer */

/*
 * always start from the beginning because line numbers are absolute
 */

	rewind(fp);

/*
 * get to the starting point of interest
 */

	if (start != 1) {
		for (i = 1; i < start; i++)
			if (!fgets(dummy, BUFSIZ, fp))
				return(-1);
	}

/*
 * copy as much as was requested
 */

	if (finish != -1) {
		for (i = start; i <= finish; i++) {
			if (!fgets(dummy, BUFSIZ, fp))
				return(-1);
			if (fputs(dummy, tfp) == EOF)
				return(-1);
		}
	}
	else {
		for (;;) {
			if (fgets(dummy, BUFSIZ, fp) == NULL) {
				if (feof(fp))
					break;
				else
					return(-1);
			}
			if (fputs(dummy, tfp) == EOF)
				return(-1);
		}
	}
	return(0);
}

/*
 *	check_ref	- to check if nextlabel are referencing
 *			  existing ttylabel
 */
static void
check_ref(void)
{
	for (const struct Gdef *g = next_def(NULL); g != NULL;
	    g = next_def(g)) {
		if (find_def(g->g_nextid) == NULL) {
			(void) printf("Warning -- nextlabel <%s> of <%s> "
			    "does not reference any existing ttylabel.\n", 
			g->g_nextid, g->g_id);
		}
	}
}

/*
 *	log	- print a message to stdout
 */

void
log(const char *msg, ...)
{
	va_list ap;
	if (lflg) {
		va_start(ap, msg);
		(void) vprintf(msg, ap);
		va_end(ap);
		(void) printf("\n");
	} else {
		va_start(ap, msg);
		(void) vfprintf(stderr, msg, ap);
		va_end(ap);
		(void) fprintf(stderr,"\n");
	}
}
