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
#include <locale.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <stddef.h>
#include <libscf.h>

#include "utils.h"
#include "scf.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	_(x)	gettext(x)

#define	CERTS_FILE_DIR	"/etc/certs/CA"
#define	CERTS_LINK_DIR	"/etc/openssl/certs"

#define	OPENSSL	"/usr/bin/openssl"

#define	FMT_VERSION	"OpenSSL Version: %s (%s)\n"
#define	MSG_OLD_HASH	"supports old hash only"
#define	MSG_NEW_HASH	"supports new hashes"

#define	FMT_WRONG	"WRONG: [%s] -> %s\n  should be: %s\n"
#define	FMT_MISSING	"MISSING: [%s] -> %s\n"
#define	FMT_DANGLING	"DANGLING: [%s] -> %s\n"
#define	FMT_UNKNOWN	"UNKNOWN TARGET: [%s] -> %s\n"

#define	MAX_HASHES 2

typedef struct cert_file {
	char *path;
	char *hash[MAX_HASHES];
	uint8_t hashcnt;

	struct cert_file *next;
} cert_file_t;

typedef struct cert_link {
	char *path;
	char *hash;
	uint8_t targetfound;

	struct cert_link *next;
} cert_link_t;

/* configuration from smf(5) */
static char *certs_file_dir = CERTS_FILE_DIR;
static char *certs_link_dir = CERTS_LINK_DIR;
static char *openssl = OPENSSL;
static int verbose = B_FALSE;
static boolean_t remove_dangling = B_TRUE;
static boolean_t remove_unknown = B_FALSE;
static boolean_t create_missing = B_TRUE;
static boolean_t correct_wrong = B_TRUE;

/* list heads */
static cert_file_t *file0 = NULL;
static cert_link_t *link0 = NULL;

#define	OP_HASH		0
#define	OP_VERSION	1
#define	OP_HASH_OLD	2
#define	NUM_OPS		3
char *
run_openssl(unsigned int op, char *arg)
{
	pid_t pid;
	int des[2];
	int i;
	ssize_t num;
	char buf[500];
	int status;

	if (op >= NUM_OPS)
		abort();

	(void) pipe(des);
	switch (pid = fork()) {
	case -1: /* error */
		err(SMF_EXIT_ERR_FATAL, _("forking child for openssl"));
		break;
	case 0: /* child */
		(void) close(des[0]);
		if (dup2(des[1], STDOUT_FILENO) == -1 || dup2(des[1],
		    STDERR_FILENO) == -1)
			err(100, NULL);
		(void) close(STDIN_FILENO);
		switch (op) {
		case OP_HASH:
			execlp(openssl, openssl, "x509", "-hash",
			    "-noout", "-in", arg, (char *)0);
			break;
		case OP_VERSION:
			execlp(openssl, openssl, "version", (char *)0);
			break;
		case OP_HASH_OLD:
			execlp(openssl, openssl, "x509",
			    "-subject_hash_old", "-noout", "-in",
			    arg, (char *)0);
			break;
		}
		printf(_("exec openssl failed: %s\n"), strerror(errno));
		exit(SMF_EXIT_ERR_FATAL);
		break;
	default: /* parent */
		(void) close(des[1]);
		num = read(des[0], &buf, sizeof (buf));
		(void) close(des[0]);

		if (num < 0)
			err(101, _("reading from openssl child"));

		buf[num] = 0;
		for (i = 0; i < num; i++) {
			if (buf[i] == '\n' || buf[i] == '\r') {
				buf[i] = 0;
				break;
			}
		}

		if (waitpid(pid, &status, 0) == -1 || !WIFEXITED(status))
			err(SMF_EXIT_ERR_FATAL,
			    _("waiting for openssl child"));
		if (WEXITSTATUS(status) != 0)
			errx(SMF_EXIT_ERR_FATAL,
			    _("error from openssl child (rc: %d): %s"),
			    WEXITSTATUS(status), buf);

		return (xstrdup(buf));
	}
}

int newossl = 0;


void
detect_openssl(void)
{
	char *vers;

	/* determine openssl version */
	vers = run_openssl(OP_VERSION, NULL);
	if (strstr(vers, "OpenSSL 1.") == vers)
		newossl = 1;
	else if (strstr(vers, "OpenSSL 0.9.") != vers)
		errx(SMF_EXIT_ERR_FATAL, _("unrecognised OpenSSL: %s"), vers);
	if (verbose)
		printf(_(FMT_VERSION), vers, (newossl ? _(MSG_NEW_HASH) :
		    _(MSG_OLD_HASH)));
	free(vers);
}

void
store_certlink(cert_link_t *cd)
{
	if (link0 == NULL) {
		link0 = cd;
	} else {
		cert_link_t *t = link0;
		while (t->next != NULL)
			t = t->next;
		t->next = cd;
	}
}

cert_link_t *
find_link_by_hash(char *hash)
{
	cert_link_t *t = link0;
	while (t != NULL) {
		if (strcmp(t->hash, hash) == 0)
			return (t);
		t = t->next;
	}
	return (NULL);
}

void
store_certfile(cert_file_t *cs)
{
	if (file0 == NULL) {
		file0 = cs;
	} else {
		cert_file_t *t = file0;
		while (t->next != NULL)
			t = t->next;
		t->next = cs;
	}
}

char *
add_dot_zero(char *str)
{
	char *ret;
	xasprintf(&ret, "%s.0", str);
	free(str);
	return (ret);
}

void
populate_hash_list(cert_file_t *cs)
{
	if (cs->path[0] != '/')
		abort();

	if (newossl)
		cs->hash[cs->hashcnt++] =
		    add_dot_zero(run_openssl(OP_HASH_OLD, cs->path));
	cs->hash[cs->hashcnt++] = add_dot_zero(run_openssl(OP_HASH, cs->path));
}

void
get_cert_file_list(void)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir(certs_file_dir);
	if (dir == NULL)
		err(SMF_EXIT_ERR_FATAL, _("could not read directory %s"),
		    certs_file_dir);

	for (de = readdir(dir); de != NULL; de = readdir(dir)) {
		char *a;
		cert_file_t *cs;

		if (strcmp(".", de->d_name) == 0 ||
		    strcmp("..", de->d_name) == 0)
			continue;

		cs = xmalloc(sizeof (*cs));
		xasprintf(&a, "%s/%s", certs_file_dir, de->d_name);
		cs->path = xrealpath(a);
		free(a);
		populate_hash_list(cs);
		store_certfile(cs);
	}
	(void) closedir(dir);
}

void
removehashlink(char *hash)
{
	char *fqhash;
	xasprintf(&fqhash, "%s/%s", certs_link_dir, hash);
	xunlink(fqhash);
	free(fqhash);
}

void
fixhashlink(char *file, char *hash)
{
	char *fqhash;
	char *relfile;

	xasprintf(&fqhash, "%s/%s", certs_link_dir, hash);
	relfile = xmakerelative(certs_link_dir, file);

	if (xexists(fqhash))
		xunlink(fqhash);

	if (symlink(relfile, fqhash) != 0)
		err(SMF_EXIT_ERR_FATAL, _("could not create symlink %s"),
		    fqhash);

	free(fqhash);
	free(relfile);
}

void
get_cert_link_list(void)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir(certs_link_dir);
	if (dir == NULL)
		err(SMF_EXIT_ERR_FATAL, _("could not read directory %s"),
		    certs_link_dir);

	for (de = readdir(dir); de != NULL; de = readdir(dir)) {
		cert_link_t *cd;
		char *a, *b;

		if (strcmp(".", de->d_name) == 0 ||
		    strcmp("..", de->d_name) == 0)
			continue;

		cd = xmalloc(sizeof (*cd));

		cd->hash = xstrdup(de->d_name);

		xasprintf(&a, "%s/%s", certs_link_dir, de->d_name);
		b = xreadlink(a);
		free(a);
		if (b[0] == '.') {
			xasprintf(&a, "%s/%s", certs_link_dir, b);
			free(b);
			b = a;
		}
		a = xrealpath(b);
		free(b);
		cd->path = a;

		store_certlink(cd);
	}
	(void) closedir(dir);
}

void
read_config(void)
{
	int a;
	char *b;

	a = get_config_boolean("verbose");
	if (a >= 0)
		verbose = a;
	a = get_config_boolean("remove_dangling");
	if (a >= 0)
		remove_dangling = a;
	a = get_config_boolean("remove_unknown");
	if (a >= 0)
		remove_unknown = a;
	a = get_config_boolean("create_missing");
	if (a >= 0)
		create_missing = a;
	a = get_config_boolean("correct_wrong");
	if (a >= 0)
		correct_wrong = a;

	b = get_config_string("certs_file_dir");
	if (b != NULL)
		certs_file_dir = b;
	b = get_config_string("certs_link_dir");
	if (b != NULL)
		certs_link_dir = b;
	b = get_config_string("openssl_command");
	if (b != NULL)
		openssl = b;
}


int
main(void)
{
	cert_file_t *tf;
	cert_link_t *tl;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (init_scf() != 0)
		errx(SMF_EXIT_ERR_FATAL, _("could not connect to smf(5): %s"),
		    scf_strerror(scf_error()));
	read_config();
	fini_scf();

#ifdef	DEBUG
	verbose = B_TRUE;
#endif

	detect_openssl();

	get_cert_link_list();
	get_cert_file_list();

	/*
	 * look at each certificate file and determine if there is
	 * a symlink to it in the link directory
	 */
	for (tf = file0; tf != NULL; tf = tf->next) {
		int j;
		for (j = 0; j < tf->hashcnt; j++) {
			tl = find_link_by_hash(tf->hash[j]);
			if (tl) {
				tl->targetfound = 1;
				if (correct_wrong && strcmp(tl->path, tf->path)
				    != 0) {
					if (verbose)
						printf(_(FMT_WRONG),
						    tf->hash[j], tl->path,
						    tf->path);
					fixhashlink(tf->path, tf->hash[j]);
				}
			} else if (create_missing) {
				if (verbose)
					printf(_(FMT_MISSING), tf->hash[j],
					    tf->path);
				fixhashlink(tf->path, tf->hash[j]);
			}
		}
	}
	/*
	 * look at each certificate link and determine if it's dangling or
	 * pointing to a certificate file which we haven't seen
	 */
	for (tl = link0; tl != NULL; tl = tl->next) {
		if (!xexists(tl->path)) {
			if (remove_dangling) {
				if (verbose)
					printf(_(FMT_DANGLING), tl->hash,
					    tl->path);
				removehashlink(tl->hash);
			}
		} else if (!tl->targetfound) {
			if (remove_unknown) {
				if (verbose)
					printf(_(FMT_UNKNOWN), tl->hash,
					    tl->path);
				removehashlink(tl->hash);
			}
		}
	}

	return (0);
}
