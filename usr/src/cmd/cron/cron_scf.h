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
 * Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
 */

#ifndef	_CRON_SCF_H
#define	_CRON_SCF_H

#ifdef	__cplusplus
extern "C" {
#endif

int init_scf(void);
void fini_scf(void);
int get_config_boolean(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _CRON_SCF_H */
