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


#ifndef	_TMSTRUCT_H
#define	_TMSTRUCT_H

/*
 * /etc/ttydefs structure
 */
struct Gdef {
	char		*g_id;		/* id for modes & speeds 	*/
	char		*g_iflags;	/* initial terminal flags 	*/
	char		*g_fflags;	/* final terminal flags 	*/
	short		g_autobaud;	/* autobaud indicator 		*/
	char		*g_nextid;	/* next id if this speed is wrong */
};

/*
 *	pmtab structure + internal data for ttymon
 */
struct pmtab {
	/* the following fields are from pmtab			*/
	char	*pmt_tag;		/* port/service tag		*/
	long	pmt_flags;	/* flags			*/
	char	*pmt_identity;	/* id for service to run as	*/
	char	*pmt_res1;	/* reserved field		*/
	char	*pmt_res2;	/* reserved field		*/
	char	*pmt_res3;	/* reserved field		*/
	char	*pmt_device;	/* full path name of device	*/
	long	pmt_ttyflags;	/* ttyflags			*/
	int	pmt_count;	/* wait_read count		*/
	char	*pmt_server;	/* full service cmd line	*/
	uint_t	pmt_timeout;	/* timeout for input 		*/
	char	*pmt_ttylabel;	/* ttylabel in /etc/ttydefs	*/
	char	*pmt_modules;	/* modules to push		*/
	char	*pmt_prompt;	/* prompt message		*/
	char	*pmt_dmsg;	/* disable message		*/
	char	*pmt_termtype;	/* terminal type		*/
	char	*pmt_softcar;	/* use softcarrier		*/

	/* the following fields are for ttymon internal use	*/
	int	pmt_status;	/* status of entry 		*/
	int	pmt_fd;		/* fd for the open device	*/
	pid_t	pmt_pid;	/* pid of child on the device 	*/
	int 	pmt_inservice;	/* service invoked		*/
	int	pmt_respawn;	/* respawn count in this series */
	long	pmt_time;	/* start time of a series	*/
	uid_t	pmt_uid;	/* uid of pmt_identity		*/
	gid_t	pmt_gid;	/* gid of pmt_identity		*/
	char	*pmt_dir;	/* home dir of pmt_identity	*/
	struct	pmtab *pmt_next;
};

/*
 *	valid flags for pmt_flags field of pmtab
 */
#define	X_FLAG	0x1	/* port/service disabled 		*/
#define	U_FLAG  0x2	/* create utmp entry for the service 	*/

/*
 *	valid flags for pmt_ttyflags field of pmtab
 */
#define	C_FLAG	0x1	/* invoke service on carrier		*/
#define	H_FLAG	0x2	/* hangup the line			*/
#define	B_FLAG	0x4	/* bi-directional line			*/
#define	R_FLAG	0x8	/* do wait_read				*/
#define	I_FLAG	0x10	/* initialize only			*/

/*
 *	autobaud enabled flag
 */
#define	A_FLAG	0x20	/* autobaud flag			*/

/*
 *	values for p_status field of pmtab
 */
#define	NOTVALID	0	/* entry is not valid		*/
#define	VALID		1	/* entry is valid		*/
#define	CHANGED		2	/* entry is valid but changed 	*/
#define	GETTY		3	/* entry is for ttymon express	*/

#endif /* _TMSTRUCT_H */
