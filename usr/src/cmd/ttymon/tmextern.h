/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_TMEXTERN_H
#define	_TMEXTERN_H

#include <stdbool.h>
#include <termios.h>
#include <termio.h>
#include <sys/termiox.h>
#include <sys/stermio.h>
#include <strlist.h>

#include "tmstruct.h"

#ifdef	__cplusplus
extern "C" {
#endif

extern void setup_PCpipe();
extern void set_softcar(struct pmtab *);
extern int find_label(FILE *, const char *);
extern const struct Gdef *get_speed(const char *);
extern void open_device(struct pmtab *);
extern bool mod_ttydefs(void);

extern int get_ttymode(int, struct termio *, struct termios *,
    struct stio *, struct termiox *, struct winsize *
#ifdef EUC
    , struct eucioc *, ldterm_cs_data_user_t *
#endif /* EUC */
    );
extern int set_ttymode(int, int, struct termio *, struct termios *,
    struct stio *, struct termiox *, struct winsize *, struct winsize *
#ifdef EUC
    , struct eucioc *, ldterm_cs_data_user_t *, int
#endif /* EUC */
    );
char *sttyparse(int, char *const *, int, struct termio *, struct termios *,
    struct termiox *, struct winsize *
#ifdef EUC
    , eucwidth_t *, struct eucioc *, ldterm_cs_data_user_t *,
    ldterm_cs_data_user_t *
#endif /* EUC */
    );

/* tmautobaud.c	*/
	extern	int	auto_termio();
	extern	char	*autobaud();

/* tmchild.c 	*/
	extern	void	write_prompt();
	extern 	void 	timedout();
	extern void tmchild(struct pmtab *);
	extern void sigpoll(void);

/* tmexpress.c 	*/
	extern	void	ttymon_express();
	extern void revokedevaccess(char *, uid_t, gid_t, mode_t);

/* tmhandler.c 	*/
	extern	void	do_poll();
	extern 	void 	sigterm();
	extern 	void 	sigchild();
	extern 	void	state_change();
	extern 	void	re_read();
	extern 	void	got_carrier();
	extern void sigpoll_catch(void);
	extern void sigalarm(int);

/* tmlock.c 	*/
	extern	int	tm_checklock();
	extern	int	tm_lock();
	extern const char *lastname(const char *);
	extern int check_session(int);

/* tmlog.c 	*/
	extern 	void 	log(const char *, ...);
	extern 	void 	fatal(const char *, ...);
	extern	void	openttymonlog(void);
	extern void opendebug(int);


/* tmparse.c 	*/
extern char *getword(const char *, size_t *, bool);
extern char quoted(const char *, size_t *);
extern bool walk_table(const char *, void (*)(uint_t, const char *), time_t *);


/* tmpeek.c 	*/
	extern	int	poll_data();
	struct strbuf *do_peek(int, int);
	extern void sigint(void);

/* tmpmtab.c 	*/
	extern	void	read_pmtab();
	extern	void	purge();
extern struct pmtab *next_pmtab(struct pmtab *);

/* tmsac.c 	*/
	extern 	void	openpid();
	extern 	void	openpipes();
	extern 	void	get_environ();
	extern	void	sacpoll();

/* tmsig.c 	*/
	extern 	void catch_signals();
	extern 	void child_sigcatch();

/* tmterm.c 	*/
	extern  int	push_linedisc();
	extern	int	set_termio();
	extern	int	initial_termio();
	extern	int	hang_up_line();
	extern	void 	flush_input();

/* tmttydefs.c 	*/
extern void read_ttydefs(void);
extern bool check_ttydefs(const char *);
extern const struct Gdef *find_def(const char *);
extern void mkargv(const char *, strlist_t *);
extern int check_flags(const char *);
const struct Gdef *next_def(const struct Gdef *);


/* tmutmp.c 	*/
	extern 	int 	account();
	extern 	void 	cleanut();
	extern void getty_account(const char *);

/* tmutil.c 	*/
	extern	int	check_device();
	extern	int	check_cmd();
	extern	void	cons_printf(const char *, ...);
	extern void safe_close(int);
	extern int strcheck(const char *, int);
	extern char *safe_strdup(const char *);
	extern int vml(const char *);
	extern void copystr(char *, const char *);
	extern bool empty(const char *);

/*
 * As questionable as this may seem, this routine is provided in
 * libnsl:
 */
extern int check_version();

extern 	void sys_name();

/* tmglobal.c 	*/
	extern	struct	pmtab	*PMtab;
	extern	int	Nentries;

	extern	int	Npollfd;
	extern struct pollfd *Pollp;

	extern struct Gdef DEFAULT;

	extern	FILE	*Logfp;
	extern	int	Sfd, Pfd;
	extern	int	PCpipe[];
	extern	int	Lckfd;

	extern	char	State;
	extern	char	*Istate;
	extern	char	*Tag;
	extern	int	Reread_flag;

	extern	int 	Maxfiles;
	extern	int 	Maxfds;

	extern	char	**environ;
	extern	char	*optarg;
	extern	int	optind, opterr;

	extern	int	Nlocked;

	extern	sigset_t	Origmask;
	extern	struct	sigaction	Sigalrm;	/* SIGALRM */
	extern	struct	sigaction	Sigcld;		/* SIGCLD */
	extern	struct	sigaction	Sigint;		/* SIGINT */
	extern	struct	sigaction	Sigpoll;	/* SIGPOLL */
	extern	struct	sigaction	Sigquit;	/* SIGQUIT */
	extern	struct	sigaction	Sigterm;	/* SIGTERM */
#ifdef	DEBUG
	extern	struct	sigaction	Sigusr1;	/* SIGUSR1 */
	extern	struct	sigaction	Sigusr2;	/* SIGUSR2 */
#endif

#ifdef	DEBUG
	extern	FILE	*Debugfp;
	extern	void	debug(const char *, ...);
#endif

	extern	uid_t	Uucp_uid;
	extern	gid_t	Tty_gid;
	extern	struct	strbuf *peek_ptr;

	extern	int	Logmaxsz;
	extern	int	Splflag;
	extern int Retry;

	extern struct rlimit Rlimit;
	extern uid_t Uucp_uid;
	extern gid_t Tty_gid;

#ifdef	__cplusplus
}
#endif

#endif	/* _TMEXTERN_H */
