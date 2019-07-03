
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
#include <strmap.h>
#include "manifest.h"


typedef enum targ_type {
	TARG_DIRECTORY = 1,
	TARG_SYMLINK,
} targ_type_t;

typedef struct targ {
	targ_type_t		targ_type;
	custr_t			*targ_path;
	custr_t			*targ_target;	/* valid for TARG_SYMLINK */
	avl_node_t		targ_node;
} targ_t;

typedef struct makeproto {
	char			*mkp_manifest;
	char			*mkp_proto;
	char			mkp_errstr[1024];
	avl_tree_t		mkp_targets;
	strmap_t		*mkp_macros;
} makeproto_t;

static int
targets_compar(const void *l, const void *r)
{
	const targ_t *ltarg = l;
	const targ_t *rtarg = r;

	int v = strcmp(custr_cstr(ltarg->targ_path),
	    custr_cstr(rtarg->targ_path));

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

void
copymacro(const char *s, strmap_t *map)
{
	char *x = NULL;
	char *eq;

	if ((x = strdup(s)) == NULL) {
		err(1, "strdup");
	}

	if ((eq = strchr(x, '=')) == NULL) {
		errx(1, "invalid macro definition: %s", s);
	}
	*eq = '\0';

	if (strmap_add(map, x, eq + 1) != 0) {
		err(1, "strmap_add");
	}

	free(x);
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

	} else if (strcmp(strlist_get(sl, 0), "l") == 0) {
		tt = TARG_SYMLINK;
		if (n < 3) {
			goto invalid;
		}
	} else {
		goto invalid;
	}

	targ_t *targ;
	if ((targ = calloc(1, sizeof (*targ))) == NULL) {
		err(1, "calloc");
	}
	targ->targ_type = tt;
	if (custr_alloc(&targ->targ_target) != 0 ||
	    custr_alloc(&targ->targ_path) != 0 ||
	    custr_appendc(targ->targ_path, '/') != 0) {
		err(1, "custr alloc");
	}

	custr_t *expanded = NULL;
	if (custr_alloc(&expanded) != 0) {
		err(1, "custr alloc");
	}

	/*
	 * First, expand any macros present in this string.
	 */
	if (manifest_macro_expand(strlist_get(sl, 1), mkp->mkp_macros,
	    expanded) != 0) {
		err(1, "expanding macros in path string");
	}

	/*
	 * Next, convert this to a normalised, fully qualified path implicitly
	 * anchored at the top of the proto area.  (i.e., "/usr" here is
	 * ultimately "$PROTO/usr").
	 */
	if (strpath_append(targ->targ_path, custr_cstr(expanded)) != 0) {
		err(1, "make path string");
	}

	if (tt == TARG_SYMLINK &&
	    custr_append(targ->targ_target, strlist_get(sl, 2)) != 0) {
		err(1, "strdup");
	}

	if (targets_insert(mkp, targ) != 0) {
		(void) snprintf(mkp->mkp_errstr, sizeof (mkp->mkp_errstr),
		    "duplicate path (%s) in manifest: \"%s\"",
		    custr_cstr(targ->targ_path), line);
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

	while ((c = getopt(argc, argv, ":f:m:o:")) != -1) {
		switch (c) {
		case 'f':
			copystring(optarg, &mkp->mkp_manifest);
			break;
		case 'm':
			copymacro(optarg, mkp->mkp_macros);
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

	if (strmap_alloc(&mkp.mkp_macros, STRMAP_F_UNIQUE_NAMES) != 0) {
		err(1, "strmap_alloc");
	}

	parse_opts(&mkp, argc, argv);

	fprintf(stderr, "manifest path: %s\n", mkp.mkp_manifest);
	fprintf(stderr, "proto: %s\n", mkp.mkp_proto);

	if (manifest_read(mkp.mkp_manifest, populate_list, &mkp) != 0) {
		if (strlen(mkp.mkp_errstr) > 0) {
			errx(1, "read_manifest_file: %s", mkp.mkp_errstr);
		} else {
			err(1, "read_manifest_file");
		}
	}

	custr_t *path = NULL;
	if (custr_alloc(&path) != 0) {
		err(1, "proto path setup");
	}

	uint_t n = 0;
	for (targ_t *t = avl_first(&mkp.mkp_targets); t != NULL;
	    t = AVL_NEXT(&mkp.mkp_targets, t)) {
		/*
		 * Take the proto-anchored path and prepend the proto path,
		 * thus making a fully qualified path to the target object.
		 */
		custr_reset(path);
		if (strpath_append(path, mkp.mkp_proto) != 0 ||
		    strpath_append(path, custr_cstr(t->targ_path)) != 0) {
			err(1, "strpath_append");
		}

		if (t->targ_type == TARG_DIRECTORY) {
			printf("[%u] mkdir \"%s\"\n", n++,
			    custr_cstr(path));
		} else {
			printf("[%u] link \"%s\" -> \"%s\"\n", n++,
			    custr_cstr(path),
			    custr_cstr(t->targ_target));
		}
	}

	custr_free(path);

	return (0);
}
