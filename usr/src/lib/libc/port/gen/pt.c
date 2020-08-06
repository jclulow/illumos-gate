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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2020 Oxide Computer Company
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#pragma weak _ptsname = ptsname
#pragma weak _grantpt = grantpt
#pragma weak _unlockpt = unlockpt

#include "lint.h"
#include "libc.h"
#include "mtlib.h"
#include <sys/types.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/mkdev.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ptms.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <wait.h>
#include <spawn.h>
#include <grp.h>
#include "tsd.h"

#define	PTSNAME "/dev/pts/"		/* slave name */
#define	PTLEN   32			/* slave name length */
#define	DEFAULT_TTY_GROUP	"tty"	/* slave device group owner */

static void itoa(int, char *);

/*
 *  Check that fd argument is a file descriptor of an opened master.
 *  Do this by sending an ISPTM ioctl message down stream. Ioctl()
 *  will fail if:(1) fd is not a valid file descriptor.(2) the file
 *  represented by fd does not understand ISPTM(not a master device).
 *  If we have a valid master, get its minor number via fstat().
 *  Concatenate it to PTSNAME and return it as the name of the slave
 *  device.
 */
static dev_t
ptsdev(int fd)
{
	struct stat64 status;
	struct strioctl istr;

	istr.ic_cmd = ISPTM;
	istr.ic_len = 0;
	istr.ic_timout = 0;
	istr.ic_dp = NULL;

	if (ioctl(fd, I_STR, &istr) < 0 || fstat64(fd, &status) < 0)
		return (NODEV);

	return (minor(status.st_rdev));
}

char *
ptsname(int fd)
{
	dev_t dev;
	char *sname;

	if ((dev = ptsdev(fd)) == NODEV)
		return (NULL);

	sname = tsdalloc(_T_PTSNAME, PTLEN, NULL);
	if (sname == NULL)
		return (NULL);
	(void) strcpy(sname, PTSNAME);
	itoa(dev, sname + strlen(PTSNAME));

	/*
	 * This lookup will create the /dev/pts node (if the corresponding
	 * pty exists.
	 */
	if (access(sname, F_OK) ==  0)
		return (sname);

	return (NULL);
}

/*
 * Send an ioctl down to the master device requesting the
 * master/slave pair be unlocked.
 */
int
unlockpt(int fd)
{
	struct strioctl istr;

	istr.ic_cmd = UNLKPT;
	istr.ic_len = 0;
	istr.ic_timout = 0;
	istr.ic_dp = NULL;

	if (ioctl(fd, I_STR, &istr) < 0)
		return (-1);

	return (0);
}

/*
 * XPG4v2 requires that open of a slave pseudo terminal device
 * provides the process with an interface that is identical to
 * the terminal interface.
 *
 * To satisfy this, in strict XPG4v2 mode, this routine also sends
 * a message down the stream that sets a flag in the kernel module
 * so that additional actions are performed when opening an
 * associated slave PTY device. When this happens, modules are
 * automatically pushed onto the stream to provide terminal
 * semantics and those modules are then informed that they should
 * behave in strict XPG4v2 mode which modifies their behaviour. In
 * particular, in strict XPG4v2 mode, empty blocks will be sent up
 * the master side of the stream rather than being suppressed.
 *
 * Most applications do not expect this behaviour so it is only
 * enabled for programs compiled in strict XPG4v2 mode (see
 * stdlib.h).
 */
int
__unlockpt_xpg4(int fd)
{
	int ret;

	if ((ret = unlockpt(fd)) == 0) {
		struct strioctl istr;

		istr.ic_cmd = PTSSTTY;
		istr.ic_len = 0;
		istr.ic_timout = 0;
		istr.ic_dp = NULL;

		if (ioctl(fd, I_STR, &istr) < 0)
			ret = -1;
	}

	return (ret);
}

int
grantpt(int fd)
{
	struct strioctl istr;
	pt_own_t pto;
	struct group *gr_name;

	/* validate the file descriptor before proceeding */
	if (ptsdev(fd) == NODEV)
		return (-1);

	pto.pto_ruid = getuid();

	gr_name = getgrnam(DEFAULT_TTY_GROUP);
	if (gr_name)
		pto.pto_rgid = gr_name->gr_gid;
	else
		pto.pto_rgid = getgid();

	istr.ic_cmd = OWNERPT;
	istr.ic_len = sizeof (pt_own_t);
	istr.ic_timout = 0;
	istr.ic_dp = (char *)&pto;

	if (ioctl(fd, I_STR, &istr) != 0) {
		errno = EACCES;
		return (-1);
	}

	return (0);
}

/*
 * Send an ioctl down to the master device requesting the master/slave pair
 * be assigned to the given zone.
 */
int
zonept(int fd, zoneid_t zoneid)
{
	struct strioctl istr;

	istr.ic_cmd = ZONEPT;
	istr.ic_len = sizeof (zoneid);
	istr.ic_timout = 0;
	istr.ic_dp = (char *)&zoneid;

	if (ioctl(fd, I_STR, &istr) != 0) {
		return (-1);
	}
	return (0);
}

static void
itoa(int i, char *ptr)
{
	int dig = 0;
	int tempi;

	tempi = i;
	do {
		dig++;
		tempi /= 10;
	} while (tempi);

	ptr += dig;
	*ptr = '\0';
	while (--dig >= 0) {
		*(--ptr) = i % 10 + '0';
		i /= 10;
	}
}

/*
 * added for SUSv3 standard
 *
 * Open a pseudo-terminal device.  External interface.
 */
int
posix_openpt(int oflag)
{
	return (open("/dev/ptmx", oflag));
}

static int
openpty_failure(int c, int s, int e)
{
	if (s >= 0) {
		(void) close(s);
	}
	if (c >= 0) {
		(void) close(c);
	}
	errno = e;
	return (-1);
}

int
openpty(int *controlp, int *subordp, char *name, const struct termios *termp,
    const struct winsize *winp)
{
	int c = -1;
	int s = -1;
	char *sname;
	int e;
	int found;

	/*
	 * Open a pseudo-terminal control device, making sure not to set it as
	 * the controlling terminal for this process:
	 */
	if ((c = posix_openpt(O_RDWR | O_NOCTTY)) < 0) {
		return (-1);
	}

	/*
	 * Set permissions and ownership on the subordinate device and unlock
	 * it:
	 */
	if (grantpt(c) < 0 || unlockpt(c) < 0) {
		return (openpty_failure(c, s, errno));
	}

	/*
	 * Open the subordinate device for this control device, again without
	 * setting it as the controlling terminal for this process:
	 */
	if ((sname = ptsname(c)) == NULL ||
	    (s = open(sname, O_RDWR | O_NOCTTY)) < 0) {
		return (openpty_failure(c, s, errno));
	}

	/*
	 * Check to see if the STREAMS modules have been automatically pushed:
	 */
	if ((found = ioctl(s, I_FIND, "ldterm")) < 0) {
		return (openpty_failure(c, s, errno));
	} else if (found == 0) {
		/*
		 * The line discipline is not present, so push the appropriate
		 * STREAMS modules for the subordinate device:
		 */
		if (ioctl(s, I_PUSH, "ptem") < 0 ||
		    ioctl(s, I_PUSH, "ldterm") < 0) {
			return (openpty_failure(c, s, errno));
		}
	}

	/*
	 * If provided, set the terminal parameters:
	 */
	if (termp != NULL && tcsetattr(s, TCSAFLUSH, termp) != 0) {
		return (openpty_failure(c, s, errno));
	}

	/*
	 * If provided, set the window size:
	 */
	if (winp != NULL && ioctl(s, TIOCSWINSZ, winp) != 0) {
		return (openpty_failure(c, s, errno));
	}

	/*
	 * If the caller wants the name of the subordinate device, copy it out.
	 *
	 * Note that this is a terrible interface: there appears to be no
	 * standard upper bound on the copy length for this pointer.  Nobody
	 * should pass anything but NULL here, preferring instead to use
	 * ptsname(3C) directly.
	 */
	if (name != NULL) {
		strcpy(name, sname);
	}

	*controlp = c;
	*subordp = s;
	return (0);
}

int
login_tty(int t)
{
	/*
	 * Use TIOCSCTTY to set this terminal device as our controlling
	 * terminal.  This will fail (with ENOTTY) if we are not the leader in
	 * our own session, so we call setsid() first.  Finally, arrange for
	 * the pseudo-terminal to occupy the standard I/O descriptors.
	 */
	if (setsid() < 0 ||
	    ioctl(t, TIOCSCTTY, 0) < 0 ||
	    dup2(t, STDIN_FILENO) < 0 ||
	    dup2(t, STDOUT_FILENO) < 0 ||
	    dup2(t, STDERR_FILENO) < 0) {
		return (-1);
	}

	/*
	 * Close the inherited descriptor, taking care to avoid closing the
	 * standard descriptors by mistake:
	 */
	if (t > STDERR_FILENO) {
		(void) close(t);
	}

	return (0);
}

int
forkpty(int *controlp, char *name, const struct termios *termp,
    const struct winsize *winp)
{
	int s;
	int c;
	int pid;

	if (openpty(&c, &s, name, termp, winp) != 0) {
		return (-1);
	}

	if ((pid = fork()) < 0) {
		return (openpty_failure(c, s, errno));
	} else if (pid > 0) {
		/*
		 * In the parent process, we close the subordinate device and
		 * return the process ID of the new child:
		 */
		(void) close(s);
		return (pid);
	}

	/*
	 * The rest of this function executes in the child process.
	 */

	/*
	 * Close the control side of the pseudo-terminal pair:
	 */
	(void) close(c);

	if (login_tty(s) != 0) {
		/*
		 * At this stage there are no particularly good ways to handle
		 * failure.  Exit as abruptly as possible, using _exit() to
		 * avoid messing with any state still shared with the parent
		 * process.
		 */
		_exit(EXIT_FAILURE);
	}

	return (0);
}
