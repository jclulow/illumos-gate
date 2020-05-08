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
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <err.h>
#include "tmstruct.h"
#include "tmextern.h"
#include "ttymon.h"

/*
 * ttyadm - format ttymon specific information and print it to stdout.
 */

static void usage(void);
static int check_label(const char *);

int
main(int argc, char *argv[])
{
	int c;
	int errflg = 0;
	struct pmtab *ptr;
	char *timeout = "";
	char *count = "";
	char prompt[BUFSIZ];
	char dmsg[BUFSIZ];
	char ttyflags[BUFSIZ], *tf;
	int dflag = 0;
	int sflag = 0;
	int lflag = 0;
	int mflag = 0;

	if (argc == 1)
		usage();
	if ((ptr = calloc(1, sizeof (*ptr))) == NULL) {
		errx(1, "failed to allocate memory");
	}
	ptr->pmt_modules = "";
	ptr->pmt_dmsg = "";
	ptr->pmt_termtype = "";
	ptr->pmt_softcar = "";
	ptr->pmt_prompt = "login\\: ";
	ttyflags[0] = '\0';
	tf = ttyflags;

	while ((c = getopt(argc, argv, "IT:S:Vd:s:chbr:t:l:m:p:i:")) != -1) {
		switch (c) {
		case 'V':
			if ((argc > 2) || (optind < argc))
				usage();
			(void)fprintf(stdout,"%d\n", PMTAB_VERS);
			exit(0);
			break;	/*NOTREACHED*/
		case 'd':
			ptr->pmt_device = optarg;
			dflag = 1;
			break;
		case 'c':
			tf = strcat(tf,"c");
			break;
		case 'h':
			tf = strcat(tf,"h");
			break;
		case 'b':
			tf = strcat(tf,"b");
			break;
		case 'I':
			tf = strcat(tf,"I");
			break;
		case 'r':
			tf = strcat(tf,"r");
			count = optarg;
			if (strcheck(optarg, NUM) != 0) {
				warnx("Invalid argument for \"-r\" -- "
				    "positive number expected.\n");
				usage();
			}
			break;
		case 'T':
			ptr->pmt_termtype = optarg;
			break;
		case 'S':
			switch (*optarg) {
			case 'Y':
			case 'y':
				ptr->pmt_softcar = "y";
				break;
			case 'N':
			case 'n':
				ptr->pmt_softcar = "n";
				break;
			default:
				usage();
			}
			break;
		case 's':
			ptr->pmt_server = optarg;
			sflag = 1;
			break;
		case 't':
			timeout = optarg;
			if (strcheck(optarg,NUM) != 0) {
				warnx("Invalid argument for \"-t\" -- "
				    "positive number expected.\n");
				usage();
			}
			break;
		case 'l':
			ptr->pmt_ttylabel = optarg;
			lflag = 1;
			break;
		case 'm':
			ptr->pmt_modules = optarg;
			mflag = 1;
			break;
		case 'p':
			ptr->pmt_prompt = prompt;
			copystr(ptr->pmt_prompt,optarg);
			break;
		case 'i':
			ptr->pmt_dmsg = dmsg;
			copystr(ptr->pmt_dmsg,optarg);
			break;
		case '?':
			usage();
			break;
		}
	}
	if (optind < argc)
		usage();

	if ((!dflag) || (!sflag) || (!lflag))
		usage();

	if (check_device(ptr->pmt_device) != 0)
		errflg++;
	if (check_cmd(ptr->pmt_server) != 0)
		errflg++;
	if (check_label(ptr->pmt_ttylabel) != 0)
		errflg++;
	if (mflag && (vml(ptr->pmt_modules) != 0))
		errflg++;
	if (errflg)
		exit(1);

	(void) fprintf(stdout, "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:",
	    ptr->pmt_device, ttyflags, count, ptr->pmt_server,
	    timeout, ptr->pmt_ttylabel, ptr->pmt_modules,
	    ptr->pmt_prompt, ptr->pmt_dmsg, ptr->pmt_termtype,
	    ptr->pmt_softcar);

	return (0);
}

/*
 * usage - print out a usage message
 */
static void
usage(void)
{
	(void) fprintf(stderr, "Usage:\tttyadm [ options ] -d device "
	    "-s service -l ttylabel\n");
	(void) fprintf(stderr, "\tttyadm -V\n");
	(void) fprintf(stderr, "\n\tValid options are:\n");
	(void) fprintf(stderr, "\t-c\n");
	(void) fprintf(stderr, "\t-h\n");
	(void) fprintf(stderr, "\t-b\n");
	(void) fprintf(stderr, "\t-I\n");
	(void) fprintf(stderr, "\t-S y|n\n");
	(void) fprintf(stderr, "\t-T term\n");
	(void) fprintf(stderr, "\t-r count\n");
	(void) fprintf(stderr, "\t-t timeout\n");
	(void) fprintf(stderr, "\t-p prompt\n");
	(void) fprintf(stderr, "\t-m modules\n");
	(void) fprintf(stderr, "\t-i msg\n");

	exit(1);
}

/*
 * check_label	- if ttylabel exists in /etc/ttydefs, return 0
 *		- otherwise, return -1
 */
static int
check_label(const char *ttylabel)
{
	FILE *fp;
	extern	int	find_label();

	if (empty(ttylabel)) {
		(void) fprintf(stderr, "error -- ttylabel is missing");
		return (-1);
	}

	if ((fp = fopen(TTYDEFS, "r")) == NULL) {
		(void)fprintf(stderr, "error -- \"%s\" does not exist, "
		    "can't verify ttylabel <%s>\n", TTYDEFS, ttylabel);
		return (-1);
	}

	if (find_label(fp, ttylabel)) {
		(void) fclose(fp);
		return (0);
	}	

	(void) fclose(fp);
	(void) fprintf(stderr,"error -- can't find ttylabel <%s> in \"%s\"\n",
	    ttylabel, TTYDEFS);
	return (-1);
}

/*
 * log - print a message to stderr
 */
void
log(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	(void) vfprintf(stderr, msg, ap);
	va_end(ap);
	(void) fprintf(stderr, "\n");
}
