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
/*
 * Copyright (c) 2018, Joyent, Inc.
 */


#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <termio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stropts.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ttymon.h"
#include "tmstruct.h"
#include "tmextern.h"
#include "sac.h"

static	struct	pmtab	*find_pid();
static	void	kill_children();

static 	struct	pmtab	*find_fd();
static	void	pcsync_close();

/*
 * fork_tmchild - fork child on the device
 */
static void
fork_tmchild(struct pmtab *pmptr)
{
	pid_t pid;
	sigset_t cset;
	sigset_t tset;
	int pcpipe0[2], pcpipe1[2];
	int p0;

#ifdef	DEBUG
	debug("in fork_tmchild");
#endif
	pmptr->pmt_inservice = FALSE;

	/*
	 * initialize pipe. 
	 * Child has pcpipe[0] pipe fd for reading and writing
	 * and closes pcpipe[1]. Parent has pcpipe[1] pipe fd for
	 * reading and writing and closes pcpipe[0].
	 *
	 * This way if the child process exits the parent's block
	 * read on pipe will return immediately as the other end of
	 * the pipe has closed. Similarly if the parent process exits
	 * child's blocking read on the pipe will return immediately.
	 */

	if (((p0 = pipe(pcpipe0)) == -1) || (pipe(pcpipe1) == -1))  {
		if (p0 == 0) {
			safe_close(pcpipe0[0]);
			safe_close(pcpipe0[1]);
		}
		log("pipe() failed: %s", strerror(errno));
		pmptr->pmt_status = VALID;
		pmptr->pmt_pid = 0;
		Retry = TRUE;
	}

	/* protect following region from SIGCLD */
	(void)sigprocmask(SIG_SETMASK, NULL, &cset);
	tset = cset;
	(void)sigaddset(&tset, SIGCLD);
	(void)sigprocmask(SIG_SETMASK, &tset, NULL);
	if ((pid = fork()) == 0) {
		/*
		 * Close all file descriptors except pmptr->pmt_fd
		 * Wait for the parent process to close its fd
		 */
		pcsync_close(pcpipe0, pcpipe1, pid, pmptr->pmt_fd);
	 	/* The CHILD */
		tmchild(pmptr); 
		/* tmchild should never return */
		fatal("tmchild for <%s> returns unexpected", pmptr->pmt_device);
	} else if (pid < 0) {
		log("fork failed: %s", strerror(errno));
		pmptr->pmt_status = VALID;
		pmptr->pmt_pid = 0;
		Retry = TRUE;
	} else {
		/*
		 * The PARENT - store pid of child and close the device
		 */
		pmptr->pmt_pid = pid;
	}
	if (pmptr->pmt_fd > 0) {
		safe_close(pmptr->pmt_fd); 
		pmptr->pmt_fd = 0; 
	}
	(void)sigprocmask(SIG_SETMASK, &cset, NULL);
	/*
	 * Wait for child to close file descriptors
	 */
	pcsync_close(pcpipe0, pcpipe1, pid, pmptr->pmt_fd);
}

/*
 * got_carrier - carrier is detected on the stream
 *	       - depends on the flags, different action is taken
 *	       - R_FLAG - wait for data
 *	       - C_FLAG - if port is not disabled, fork tmchild
 *	       - A_FLAG - wait for data 
 *	       - otherwise - write out prompt, then wait for data
 */
void
got_carrier(struct pmtab *pmptr)
{
	flush_input(pmptr->pmt_fd);

	if (pmptr->pmt_ttyflags & R_FLAG) {
#ifdef	DEBUG
	debug("R_FLAG");
#endif
		return;
	} 
	else if ((pmptr->pmt_ttyflags & (C_FLAG|B_FLAG)) &&
		(State != PM_DISABLED) &&
		(!(pmptr->pmt_flags & X_FLAG))) {
		fork_tmchild(pmptr);
	}
	else if (pmptr->pmt_ttyflags & A_FLAG) {
#ifdef	DEBUG
	debug("A_FLAG");
#endif
		return;
	}
	else if (pmptr->pmt_timeout) {
		fork_tmchild(pmptr);
	}
	else if ( ! (pmptr->pmt_ttyflags & X_FLAG) ) {
		write_prompt(pmptr->pmt_fd,pmptr,TRUE,TRUE);
	}
}

/*
 * got_data - data is detected on the stream, fork tmchild
 */
static void
got_data(struct pmtab *pmptr)
{
	struct sigaction sigact;

	if (tm_checklock(pmptr->pmt_fd) != 0) {
		pmptr->pmt_status = LOCKED;
		safe_close(pmptr->pmt_fd);
		pmptr->pmt_fd = 0;
		Nlocked++;
		if (Nlocked == 1) {
			sigact.sa_flags = 0;
			sigact.sa_handler = sigalarm;
			(void)sigemptyset(&sigact.sa_mask);
			(void)sigaction(SIGALRM, &sigact, NULL);
			(void)alarm(ALARMTIME);
		}
	}
	else 
		fork_tmchild(pmptr);
}
/*
 * got_hup - stream hangup is detected, close the device
 */
static void
got_hup(struct pmtab *pmptr)
{
#ifdef	DEBUG
	debug("in got hup");
#endif
	safe_close(pmptr->pmt_fd);
	pmptr->pmt_fd = 0;
	pmptr->pmt_inservice = 0;
	Retry = TRUE;
}


/*
 *	do_poll	- poll device
 *		- if POLLHUP received, close the device
 *		- if POLLIN received, fork tmchild.
 */
void
do_poll(struct pollfd *fdp, int nfds)
{
	int i, n;
	struct pmtab *pmptr;

	n = poll(fdp, (unsigned long)nfds, -1);	/* blocked poll */
#ifdef	DEBUG
	debug("poll return");
#endif

	if (n < 0) {
		if (errno == EINTR)	/* interrupt by signal */
			return;
		fatal("do_poll: poll failed: %s", strerror(errno));
	}
	for (i = 0; (i < nfds)&&(n); i++,fdp++) {
		if (fdp->revents != 0) {
			n--;
			if ((pmptr = find_fd(fdp->fd)) == NULL) {
				log("do_poll: cannot find fd %d in pmtab",
				    fdp->fd);
				continue;
			} else if (fdp->revents & POLLHUP) {
				got_hup(pmptr);
			} else if (fdp->revents & POLLIN) {
#ifdef	DEBUG
				debug("got POLLIN");
#endif
				got_data(pmptr);
			} else if (fdp->revents & POLLERR) {
				fatal("ttymon[%d]: do_poll: POLLERR on fd %d",
				    getpid(), fdp->fd);
			}
		}
	}
}

/*
 *	sigchild	- handler for SIGCLD
 *			- find the pid of dead child
 *			- clean utmp if U_FLAG is set
 */
void
sigchild(int n)
{
	struct pmtab *pmptr;
	siginfo_t info;
	int status;
	pid_t pid;
	int rcode;

#ifdef	DEBUG
	debug("in sigchild");
#endif

	/* find all processes that died */
	for (;;) {
		rcode = waitid(P_ALL, 0, &info, WNOHANG|WEXITED);
		if (rcode == -1 && errno == EINTR)
			continue;

		/* If no more children have exited, just return */
		if (rcode == -1 || (pid = info.si_pid) == 0)
			break;

		/* construct status as returned from waitid() */
		status = info.si_status & 0377;
		switch (info.si_code) {
		case CLD_EXITED:
			status <<= 8;
			break;
		case CLD_DUMPED:
			status |= WCOREFLG;
			break;
		case CLD_KILLED:
			break;
		}

		if ((pmptr = find_pid(pid)) == NULL) {
#ifdef	DEBUG
			log("cannot find dead child (%ld) in pmtab", pid);
#endif
			/*
			 * This may happen if the entry is deleted from pmtab
			 * before the service exits.
			 * We try to cleanup utmp entry
			 */
			cleanut(pid, status);
		} else {
			if (pmptr->pmt_flags & U_FLAG)
				cleanut(pid, status);
			pmptr->pmt_status = VALID;
			pmptr->pmt_fd = 0;
			pmptr->pmt_pid = 0;
			pmptr->pmt_inservice = 0;
			Retry = TRUE;
		}
	}
}

/*
 * sigterm - handler for SIGTERM
 */
void
sigterm(void)
{
	fatal("caught SIGTERM");
}

/*
 * state_change	- this is called when ttymon changes
 *		  its internal state between enabled and disabled
 */
void
state_change(void)
{
	struct pmtab *pmptr;

#ifdef	DEBUG
	debug("in state_change");
#endif

	/* 
	 * closing PCpipe will cause attached non-service children 
	 * to get SIGPOLL and exit
	 */
	safe_close(PCpipe[0]);
	safe_close(PCpipe[1]);

	/* reopen PCpipe */
	setup_PCpipe();

	/*
	 * also close all open ports so ttymon can start over
	 * with new internal state
	 */
	for (pmptr = PMtab; pmptr; pmptr = pmptr->pmt_next) {
		if (pmptr->pmt_fd > 0 && pmptr->pmt_pid == 0) {
			safe_close(pmptr->pmt_fd);
			pmptr->pmt_fd = 0;
		}
	}
	Retry = TRUE;
}

/*
 * re_read	- reread pmtab
 *		- kill tmchild if entry changed
 */
void
re_read(void)
{
	extern	struct	pollfd	*Pollp;
	sigset_t	cset;
	sigset_t	tset;

	(void)sigprocmask(SIG_SETMASK, NULL, &cset);
	tset = cset;
	(void)sigaddset(&tset, SIGCLD);
	(void)sigprocmask(SIG_SETMASK, &tset, NULL);
	if (Nlocked > 0) {
		(void) alarm(0);
		Nlocked = 0;
	}
	read_pmtab();
	kill_children();
	(void)sigprocmask(SIG_SETMASK, &cset, NULL);
	purge();

	if (Nentries > Npollfd) {
#ifdef	DEBUG
		debug("Nentries > Npollfd, reallocating pollfds");
#endif
		/* need to malloc more pollfd structure */
		free(Pollp);
		Npollfd = Nentries + 10;
		if (Npollfd > Maxfds)
			Npollfd = Maxfds;
		if ((Pollp = calloc(Npollfd, sizeof (struct pollfd))) ==
		    NULL) {
			fatal("malloc for Pollp failed");
		}
	}
	Retry = TRUE;
}

/*
 * find_pid(pid) - find the corresponding pmtab entry for the pid
 */
static struct pmtab *
find_pid(pid_t pid)
{
	for (struct pmtab *pmt = PMtab; pmt != NULL; pmt = pmt->pmt_next) {
		if (pmt->pmt_pid == pid) {
			return (pmt);
		}
	}

	return (NULL);
}

/*
 * find_fd(fd) - find the corresponding pmtab entry for the fd
 */
static struct pmtab *
find_fd(int fd)
{
	for (struct pmtab *pmt = PMtab; pmt != NULL; pmt = pmt->pmt_next) {
		if (pmt->pmt_fd == fd) {
			return (pmt);
		}
	}

	return (NULL);
}

/*
 * kill_children()	- if the pmtab entry has been changed,
 *			  kill tmchild if it is not in service.
 *			- close the device if there is no tmchild
 */
static void
kill_children(void)
{
	for (struct pmtab *pmt = PMtab; pmt != NULL; pmt = pmt->pmt_next) {
		if (pmt->pmt_status == VALID)
			continue;

		if (pmt->pmt_fd > 0 && pmt->pmt_pid == 0) {
			safe_close(pmt->pmt_fd);
			pmt->pmt_fd = 0;
		} else if (pmt->pmt_fd == 0 && pmt->pmt_pid > 0 &&
		    pmt->pmt_inservice == FALSE) {
			(void) kill(pmt->pmt_pid, SIGTERM);
		}
	}
}

static void
mark_service(pid_t pid)
{
	struct pmtab *pmptr;

#ifdef	DEBUG
	debug("in mark_service");
#endif

	if ((pmptr = find_pid(pid)) == NULL) {
		log("mark_service: cannot find child (%ld) in pmtab", pid);
		return;
	}

	pmptr->pmt_inservice = TRUE;
}

/*
 * read_pid(fd) - read pid info from PCpipe
 */
static void
read_pid(int fd)
{
	int ret;
	pid_t pid;

	for (;;) {
		if ((ret = read(fd,&pid,sizeof(pid))) < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) 
				return;
			fatal("read PCpipe failed: %s", strerror(errno));
		}
		if (ret == 0)
			return;
		if (ret != sizeof(pid))
			fatal("read return size incorrect, ret = %d", ret);

		mark_service(pid);
	}
}

/*
 * sipoll_catch()	- signal handle of SIGPOLL for ttymon
 *			- it will check both PCpipe and pmpipe
 */
void
sigpoll_catch(void)
{
	int ret;
	struct pollfd pfd[2];

#ifdef	DEBUG
	debug("in sigpoll_catch");
#endif

	pfd[0].fd = PCpipe[0];
	pfd[1].fd = Pfd;
	pfd[0].events = POLLIN;
	pfd[1].events = POLLIN;
	if ((ret = poll(pfd, 2, 0)) < 0)
		fatal("sigpoll_catch: poll failed: %s", strerror(errno));

	if (ret > 0) {
		if (pfd[0].revents & POLLIN) 
			read_pid(pfd[0].fd);
		if (pfd[1].revents & POLLIN)
			sacpoll();
	}
}

void
sigalarm(int signo)
{
	struct sigaction sigact;
	int fd;
	extern int check_session();

#ifdef	DEBUG
	debug("in sigalarm, Nlocked = %d", Nlocked);
#endif

	for (struct pmtab *pmt = PMtab; pmt != NULL; pmt = pmt->pmt_next) {
		if (pmt->pmt_status == LOCKED && pmt->pmt_fd == 0) {
			if ((fd = open(pmt->pmt_device,
			    O_RDWR | O_NONBLOCK)) == -1) {
				log("open (%s) failed: %s", pmt->pmt_device,
				    strerror(errno));
				pmt->pmt_status = VALID;
				Nlocked--;
				Retry = TRUE;
			} else {
				if (tm_checklock(fd) == 0) {
					Nlocked--;
					pmt->pmt_fd = fd;
					Retry = TRUE;
				} else {
					safe_close(fd);
				}
			}
		} else if (pmt->pmt_status == SESSION && pmt->pmt_fd == 0) {
			if ((fd = open(pmt->pmt_device,
			    O_RDWR | O_NONBLOCK)) == -1) {
				log("open (%s) failed: %s", pmt->pmt_device,
				    strerror(errno));
				pmt->pmt_status = VALID;
				Nlocked--;
				Retry = TRUE;
			} else {
				if (check_session(fd) == 0) {
					Nlocked--;
					pmt->pmt_fd = fd;
					Retry = TRUE;
				} else {
					safe_close(fd);
				}
			}
		} else if (pmt->pmt_status == UNACCESS && pmt->pmt_fd == 0) {
			if ((fd = open(pmt->pmt_device,
			    O_RDWR | O_NONBLOCK)) == -1) {
				log("open (%s) failed: %s", pmt->pmt_device,
				    strerror(errno));
				pmt->pmt_status = VALID;
				Nlocked--;
				Retry = TRUE;
			} else { 
				Nlocked--;
				pmt->pmt_fd = fd;
				Retry = TRUE;
			}
		}
	}

	sigact.sa_flags = 0;
	sigact.sa_handler = (Nlocked > 0) ? sigalarm : SIG_IGN;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaction(SIGALRM, &sigact, NULL);
	if (Nlocked > 0) {
		(void) alarm(ALARMTIME);
	}
}

/*
 * pcsync_close -  For the child process close all open fd's except
 * the one that is passed to the routine. Coordinate the reads and
 * writes to the pipes by the parent and child process to ensure
 * the parent and child processes have closed all the file descriptors
 * that are not needed any more.
 */
static void
pcsync_close(int *p0, int *p1, int pid, int fd)
{
	char	ch;

	if (pid == 0) {				/* Child */
		struct  pmtab   *tp;
		for (tp = PMtab; tp; tp = tp->pmt_next) {
			if ((tp->pmt_fd > 0) && (tp->pmt_fd != fd)) {
				safe_close(tp->pmt_fd);
			}
		}
		safe_close(p0[1]);
		safe_close(p1[0]);
		if (read(p0[0], &ch, 1) == 1) {
			(void) write(p1[1], "a", 1);
		}
		safe_close(p0[0]);
		safe_close(p1[1]);
	} else {				/* Parent */
		safe_close(p0[0]);
		safe_close(p1[1]);
		if (write(p0[1], "a", 1) == 1) {
			(void) read(p1[0], &ch, 1);
		}
		safe_close(p0[1]);
		safe_close(p1[0]);
	}
}
