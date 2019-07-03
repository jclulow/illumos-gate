
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <err.h>
#include <errno.h>
#include <sys/avl.h>

#include <strpath.h>
#include "manifest.h"


typedef enum targ_type {
	TARG_DIRECTORY = 1,
	TARG_SYMLINK,
} targ_type_t;

typedef struct targ {
	targ_type_t		targ_type;
	char			*targ_path;
	char			*targ_target;	/* valid for TARG_SYMLINK */
	avl_node_t		targ_node;
} targ_t;

typedef struct makeproto {
	char			*mkp_manifest;
	char			*mkp_proto;
	char			mkp_errstr[1024];
	avl_tree_t		mkp_targets;
} makeproto_t;

static int
targets_compar(const void *l, const void *r)
{
	const targ_t *ltarg = l;
	const targ_t *rtarg = r;

	int v = strcmp(ltarg->targ_path, rtarg->targ_path);

	return (v < 0 ? -1 : v > 0 ? 1 : 0);
}

static int
targets_insert(makeproto_t *mkp, targ_t *t)
{
	avl_index_t where;

	if (avl_find(&mkp->mkp_targets, t, &where) != NULL) {
		errno = EEXIST;
		return (-1);
	}

	avl_insert(&mkp->mkp_targets, t, where);
	return (0);
}

void
copystring(const char *s, char **out)
{
	free(*out);
	if ((*out = strdup(s)) == NULL) {
		err(1, "strdup");
	}
}

static void
dump_strlist(strlist_t *sl)
{
	uint_t len = strlist_contig_count(sl);

	printf("[ ");
	for (uint_t n = 0; n < len; n++) {
		if (n > 0) {
			printf(", ");
		}
		printf("\"%s\"", strlist_get(sl, n));
	}
	printf("%s]", len > 0 ? " " : "");
}

static me_cb_ret_t
populate_list(const char *line, strlist_t *sl, void *arg)
{
	makeproto_t *mkp = arg;
	uint_t n = strlist_contig_count(sl);
	targ_type_t tt;

	if (n < 1) {
		return (MECB_NEXT);
	}

	if (strcmp(strlist_get(sl, 0), "d") == 0) {
		tt = TARG_DIRECTORY;
		if (n < 2) {
			goto invalid;
		}

	} else if (strcmp(strlist_get(sl, 0), "s") == 0) {
		tt = TARG_SYMLINK;
		if (n < 3) {
			goto invalid;
		}
	} else {
		goto invalid;
	}

	custr_t *cu;
	if (custr_alloc(&cu) != 0 || custr_appendc(cu, '/') != 0 ||
	    strpath_append(cu, strlist_get(sl, 1)) != 0) {
		err(1, "make path string");
	}

	targ_t *targ;
	if ((targ = calloc(1, sizeof (*targ))) == NULL) {
		err(1, "calloc");
	}

	targ->targ_type = tt;
	if ((targ->targ_path = strndup(custr_cstr(cu), custr_len(cu))) ==
	    NULL) {
		err(1, "strndup");
	}
	custr_free(cu);

	if (tt == TARG_SYMLINK &&
	    (targ->targ_target = strdup(strlist_get(sl, 2))) == NULL) {
		err(1, "strdup");
	}

	if (targets_insert(mkp, targ) != 0) {
		(void) snprintf(mkp->mkp_errstr, sizeof (mkp->mkp_errstr),
		    "duplicate path in manifest: \"%s\"", line);
		return (MECB_CANCEL);
	}

	return (MECB_NEXT);

invalid:
	printf("invalid manifest line: ");
	dump_strlist(sl);
	printf("\n");

	(void) snprintf(mkp->mkp_errstr, sizeof (mkp->mkp_errstr),
	    "invalid manifest line: \"%s\"", line);

	return (MECB_CANCEL);
}

static void
parse_opts(makeproto_t *mkp, int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, ":f:o:")) != -1) {
		switch (c) {
		case 'f':
			copystring(optarg, &mkp->mkp_manifest);
			break;
		case 'o':
			copystring(optarg, &mkp->mkp_proto);
			break;
		case ':':
			(void) fprintf(stderr, "Option -%c requires an "
			    "operand\n", optopt);
			exit(1);
			break;
		case '?':
			(void) fprintf(stderr, "Unrecognised option: -%c\n",
			    optopt);
			exit(1);
			break;
		}
	}

	if (mkp->mkp_manifest == NULL || mkp->mkp_proto == NULL) {
		errx(1, "Must provide -f and -o options");
	}
}

int
main(int argc, char *argv[])
{
	makeproto_t mkp;
	bzero(&mkp, sizeof (mkp));

	avl_create(&mkp.mkp_targets, targets_compar, sizeof (targ_t),
	    offsetof(targ_t, targ_node));

	parse_opts(&mkp, argc, argv);

	fprintf(stderr, "manifest path: %s\n", mkp.mkp_manifest);
	fprintf(stderr, "proto: %s\n", mkp.mkp_proto);

	if (read_manifest_file(mkp.mkp_manifest, populate_list, &mkp) != 0) {
		if (strlen(mkp.mkp_errstr) > 0) {
			errx(1, "read_manifest_file: %s", mkp.mkp_errstr);
		} else {
			err(1, "read_manifest_file");
		}
	}

	uint_t n = 0;
	for (targ_t *t = avl_first(&mkp.mkp_targets); t != NULL;
	    t = AVL_NEXT(&mkp.mkp_targets, t)) {
		if (t->targ_type == TARG_DIRECTORY) {
			printf("[%u] mkdir \"%s\"\n", n++, t->targ_path);
		} else {
			printf("[%u] link \"%s\" -> \"%s\"\n", n++,
			    t->targ_path, t->targ_target);
		}
	}

	return (0);
}
