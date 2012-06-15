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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <err.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <stddef.h>
#include <libscf.h>

#include "utils.h"

#define	_(x)	gettext(x)

void *
xmalloc(size_t sz)
{
	void *x = malloc(sz);
	if (x == NULL)
		abort();
	bzero(x, sz);
	return (x);
}

char *
xstrdup(const char *a)
{
	char *x = strdup(a);
	if (x == NULL)
		abort();
	return (x);
}

int
xasprintf(char **str, const char *format, ...)
{
	va_list ap;
	int ret;

	*str = NULL;
	va_start(ap, format);
	ret = vasprintf(str, format, ap);
	va_end(ap);

	if (ret == -1)
		abort();

	return (ret);
}

int
xexists(char *path)
{
	struct stat buf;
	if (stat(path, &buf) != 0) {
		if (errno == ENOENT)
			return (0);
		else
			err(SMF_EXIT_ERR_FATAL, _("stat on path: %s"), path);
	}
	return (1);
}

char *
xreadlink(char *path)
{
	char tmp[PATH_MAX];
	int len;

	len = readlink(path, tmp, sizeof (tmp) - 1);
	if (len == -1 || len >= (int) sizeof (tmp))
		err(SMF_EXIT_ERR_FATAL, _("readlink failure on path: %s"),
		    path);
	tmp[len] = '\0'; /* NUL-terminate what readlink gives us */

	return (xstrdup(tmp));
}

char *
xrealpath(char *path)
{
	char *ret;
	char tmp[PATH_MAX];

	ret = realpath(path, tmp);
	if (ret == NULL) {
		if (errno == ENOENT)
			return (xstrdup(path));
		else
			err(SMF_EXIT_ERR_FATAL, _("realpath failure on path: %s"),
			    path);
	}

	return (xstrdup(tmp));
}

void
xunlink(const char *path)
{
	if (unlink(path) != 0)
		err(SMF_EXIT_ERR_FATAL, _("could not unlink: %s"), path);
}

char *
xmakerelative(char *relativetodir, char *path)
{
	int i;
	int comlen = 0;
	int extraelems = 0;
	char tmp[PATH_MAX];
	char *lastsrc, *lastpath, *srccomp, *pathcomp;
	char *trelativetodir = strdup(relativetodir);
	char *tpath = strdup(path);

	if (relativetodir[0] != '/' || path[0] != '/')
		abort();

	srccomp = strtok_r(trelativetodir, "/", &lastsrc);
	pathcomp = strtok_r(tpath, "/", &lastpath);

	/* discard elements common to both paths */
	while (srccomp != NULL && pathcomp != NULL &&
	    strcmp(srccomp, pathcomp) == 0) {
		srccomp = strtok_r(NULL, "/", &lastsrc);
		pathcomp = strtok_r(NULL, "/", &lastpath);
	}
	/* record the start of the unique part of the target path */
	comlen = pathcomp - tpath;
	/* count the number of non-common path elements in the target dir */
	while (srccomp != NULL) {
		extraelems++;
		srccomp = strtok_r(NULL, "/", &lastsrc);
	}

	if (extraelems * 3 + strlen(&path[comlen]) + 1 > PATH_MAX)
		errx(17, "relative path generation error");

	/*
	 * generate a path that escapes only the non-common elements of the
	 * target directory
	 */
	tmp[0] = '\0';
	for (i = 0; i < extraelems; i++)
		strcat(tmp, "../");
	strcat(tmp, &path[comlen]);

	free(trelativetodir);
	free(tpath);

	return (strdup(tmp));
}
