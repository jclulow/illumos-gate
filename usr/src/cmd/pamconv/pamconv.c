
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define	PAM_CONFIG	"/etc/pam.conf"
#define	PAM_CONFIG_DIR	"/etc/pam.d"

#define	SENTINEL0	" CDDL HEADER END"
#define SENTINEL1	" present in this file in previous releases are " \
			"still acceptable."
#define SENTINEL2	" Authentication management"

#define	LEGACY_CONTENTS	"#\n" \
			"# Legacy PAM Configuration\n" \
			"#\n" \
			"# The shipped PAM configuration has moved from " \
				"the legacy " PAM_CONFIG "\n" \
			"# to the new " PAM_CONFIG_DIR " model.  See " \
				"pam.conf(4) for more information.\n"


typedef struct pamline {
	char *service;
	char *copyfrom;
	char *commentfrom;
	struct pamline *next;
} pamline_t;

typedef struct servicelist {
	char *service;
	struct servicelist *next;
} servicelist_t;


static int fd;
static char *f;
static size_t flen;

static pamline_t *all = NULL;
static servicelist_t *services = NULL;

static char *pam_config = PAM_CONFIG;
static char *pam_config_dir = PAM_CONFIG_DIR;

static boolean_t preview = B_FALSE;
static boolean_t verbose = B_FALSE;
static boolean_t replace_original = B_FALSE;

static boolean_t onlycomments = B_TRUE;


static void
store_service(char *service)
{
	servicelist_t *sl = calloc(1, sizeof (servicelist_t));
	sl->service = service;
	if (services == NULL) {
		services = sl;
	} else {
		servicelist_t *t = services;
		while (t != NULL) {
			if (strcmp(t->service, sl->service) == 0)
				return;
			if (t->next == NULL) {
				t->next = sl;
				break;
			}
			t = t->next;
		}
	}
}

static void
print_service(FILE *file, char *service)
{
	pamline_t *t = all;
	while (t != NULL) {
		if (t->service && strcmp(t->service, service) == 0) {
			if (t->copyfrom && fprintf(file, "%s",
			    t->copyfrom) < 0)
				err(2, "could not write file");
			if (t->commentfrom && fprintf(file, "#%s",
			    t->commentfrom) < 0)
				err(2, "could not write file");
			if (fprintf(file, "\n") < 0)
				err(2, "could not write file");
		}
		t = t->next;
	}
}

static void
write_service_file(char *service)
{
	FILE *out;
	char *path;

	if (asprintf(&path, "%s/%s", pam_config_dir, service) < 0)
		err(2, "could not asprintf");
	if (verbose)
		(void) fprintf(stderr, "service '%s' -> %s\n", service, path);
	out = fopen(path, "w+");
	if (out == NULL)
		err(2, "could not open %s for write", path);
	free(path);

	print_service(out, service);

	(void) fclose(out);
}

static void
write_legacy_file(void)
{
	FILE *out;

	if (verbose)
		(void) fprintf(stderr, "replacing %s with placeholder file",
		    pam_config);

	out = fopen(pam_config, "w+");
	if (out == NULL)
		err(2, "could not open %s for write", pam_config);

	fprintf(out, LEGACY_CONTENTS);

	(void) fclose(out);
}

static void
store_pamline(pamline_t *add)
{
	if ((add->service && strlen(add->service) > 0) ||
	    (add->copyfrom && strlen(add->copyfrom) > 0))
		onlycomments = B_FALSE;

	/*
	 * If we find the end of various known header block strings,
	 * and we've thus far only seen a block comment, then turf
	 * all existing lines.
	 */
	if (all && onlycomments && add->commentfrom &&
	    (strcmp(SENTINEL0, add->commentfrom) == 0 ||
	    strcmp(SENTINEL1, add->commentfrom) == 0 ||
	    strcmp(SENTINEL2, add->commentfrom) == 0)) {
		pamline_t *pres, *t = all;
		while (t != NULL) {
			pres = t->next;
			free(t);
			t = pres;
		}
		all = NULL;
		free(add);
		return;
	}

	if (add->service != NULL)
		store_service(add->service);

	if (all == NULL) {
		all = add;
	} else {
		pamline_t *t = all;
		while (t != NULL) {
			if (add->service != NULL && t->service == NULL) {
				/* apply this service to all unclaimed lines */
				t->service = add->service;
			}
			if (t->next == NULL) {
				t->next = add;
				break;
			}
			t = t->next;
		}
	}
}

static void
open_pam_conf(char *filename)
{
	struct stat st;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		/* If there is no /etc/pam.conf, then silently exit. */
		if (errno == ENOENT) {
			if (verbose)
				(void) fprintf(stderr, "no %s found;"
				    " not running.\n", pam_config);
			exit(0);
		} else {
			err(2, "could not open %s", filename);
		}
	}

	if (fstat(fd, &st) == -1)
		err(2, "could not stat %s", filename);
	flen = st.st_size;

	f = mmap(NULL, flen, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (f == MAP_FAILED)
		err(2, "could not mmap %s", filename);
}

static void
close_pam_conf(void)
{
	(void) munmap(f, flen);
	(void) close(fd);
}

static pamline_t *
new_pamline(void)
{
	pamline_t *pl = calloc(1, sizeof (pamline_t));
	if (pl == NULL)
		abort();
	return (pl);
}

static void
find_lines(void)
{
	char *pos;
	int state = 0;
	pamline_t *t = new_pamline();
	boolean_t prelimwhitespace = B_FALSE;

	t->copyfrom = f;
 	for (pos = f; pos < f + flen; pos++) {
		switch (state) {
		case 0:
			switch (*pos) {
			case '#':
				*pos = '\0';

				t->commentfrom = pos + 1;

				prelimwhitespace = B_FALSE;
				state = 1;
				break;
			case ' ':
			case '\t':
				*pos = '\0';

				t->service = t->copyfrom;
				t->copyfrom = pos + 1;

				prelimwhitespace = B_TRUE;
				state = 1;
				break;
			case '\n':
				*pos = '\0';

				store_pamline(t);

				t = new_pamline();
				t->copyfrom = pos + 1;
				break;
			}
			break;
		case 1:
			switch (*pos) {
			case ' ':
			case '\t':
				if (prelimwhitespace)
					t->copyfrom++;
				break;
			case '\n':
				*pos = '\0';

				store_pamline(t);

				t = new_pamline();
				t->copyfrom = pos + 1;

				state = 0;
				break;
			default:
				prelimwhitespace = B_FALSE;
			}
		}
	}
}

static void
output_services(void)
{
	servicelist_t *s = services;

	while (s != NULL) {
		if (preview) {
			(void) fprintf(stdout, "------------ %s/%s :\n",
			    pam_config_dir, s->service);
			print_service(stdout, s->service);
			(void) fprintf(stdout, "\n");
		} else {
			write_service_file(s->service);
		}
		s = s->next;
	}
}

int
main(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, ":nvri:o:")) != -1) {
		switch (c) {
		case 'v':
			verbose = B_TRUE;
			break;
		case 'n':
			preview = B_TRUE;
			break;
		case 'r':
			replace_original = B_TRUE;
			break;
		case 'i':
			pam_config = optarg;
			break;
		case 'o':
			pam_config_dir = optarg;
			break;
		case ':':
			errx(1, "Option -%c requires an operand", optopt);
			break;
		case '?':
			errx(1, "Unrecognised option: -%c", optopt);
			break;
		}
	}

	if (verbose) {
		(void) fprintf(stderr, "input file: %s\n", pam_config);
		(void) fprintf(stderr, "output dir: %s\n", pam_config_dir);
	}

	open_pam_conf(pam_config);
	find_lines();

	/*
	 * If we haven't found any non-trivial lines, then exit now.
	 */
	if (onlycomments) {
		if (verbose)
			(void) fprintf(stderr, "trivial %s detected; not "
			    "running.\n", pam_config);
		goto done;
	}

	output_services();

	if (!preview && replace_original)
		write_legacy_file();

done:
	close_pam_conf();
	return (0);
}
