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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <assert.h>

#include <libscf.h>

#include "cron_scf.h"

extern void *xmalloc(size_t); /* from funcs.c */

static char *fmri;
static scf_handle_t *scf;
static scf_instance_t *inst;

/*
 * Initialise our connection to smf(5).  Returns:
 *    0 on success
 *   <0 for any failure
 *   -2 if we believe we're not actually running under smf(5)
 */
int
init_scf(void)
{
	int rc = -1;
	size_t fmrisz;

	assert(scf == NULL);

	scf = scf_handle_create(SCF_VERSION);
	if (scf == NULL)
		return (-1);
	if (scf_handle_bind(scf) != 0)
		goto cleanup0;

#ifdef DEBUG
	if (getenv("SMF_TEST_FMRI") != NULL) {
		printf("DEBUG: smf test mode engaged\n");
		fmri = strdup(getenv("SMF_TEST_FMRI"));
		goto have_fmri;
	}
#endif /* DEBUG */

	fmrisz = scf_myname(scf, NULL, 0);
	if (fmrisz == -1) {
		if (scf_error() == SCF_ERROR_NOT_SET) {
			rc = -2;
		}
		goto cleanup1;
	}
	fmri = xmalloc(fmrisz + 1);
	fmrisz = scf_myname(scf, fmri, fmrisz + 1);
	if (fmrisz == -1)
		goto cleanup2;

have_fmri:

	if ((inst = scf_instance_create(scf)) == NULL)
		goto cleanup2;

	if (scf_handle_decode_fmri(scf, fmri, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0)
		goto cleanup3;

	return (0);

cleanup3:
	scf_instance_destroy(inst);
	inst = NULL;
cleanup2:
	free(fmri);
	fmri = NULL;
cleanup1:
	(void) scf_handle_unbind(scf);
cleanup0:
	scf_handle_destroy(scf);
	scf = NULL;
	return (rc);
}

void
fini_scf(void)
{
	assert(scf != NULL);

	(void) scf_instance_destroy(inst);
	inst = NULL;
	free(fmri);
	fmri = NULL;
	(void) scf_handle_unbind(scf);
	(void) scf_handle_destroy(scf);
	scf = NULL;
}

/*
 * Fetch the boolean value of a property from the 'config' property
 * group in our smf(5) instance.
 * Returns:
 *   <0 on failure
 *    0 if found and false
 *    1 if found and true
 */
int
get_config_boolean(char *name)
{
	static scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	uint8_t out;
	int rc = -1;

	assert(scf != NULL);

	if (scf_instance_get_pg_composed(inst, NULL, "config", pg) != 0)
		goto cleanup0;

	prop = scf_property_create(scf);
	val = scf_value_create(scf);
	if (prop == NULL || val == NULL)
		goto cleanup0;

	if (scf_pg_get_property(pg, name, prop) != 0)
		goto cleanup0;

	if (scf_property_is_type(prop, SCF_TYPE_BOOLEAN) != 0)
		goto cleanup0;

	if (scf_property_get_value(prop, val) != 0)
		goto cleanup0;

	if (scf_value_get_boolean(val, &out) != 0)
		goto cleanup0;

	rc = out;

cleanup0:
	if (val != NULL)
		scf_value_destroy(val);
	if (prop != NULL)
		scf_property_destroy(prop);
	if (pg != NULL)
		scf_pg_destroy(pg);

	return (rc);
}
