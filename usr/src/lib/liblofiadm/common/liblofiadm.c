#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <strings.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/mkdev.h>
#include <sys/cred.h>
#include <sys/cmlb.h>
#include <sys/lofi.h>

#include "ilstr.h"
#include "liblofiadm.h"

typedef enum lofiadm_mode {
	LOFIADM_MODE_REST = 0,
	LOFIADM_MODE_WALK,
	LOFIADM_MODE_LOOKUP,
} lofiadm_mode_t;

struct lofiadm {
	lofiadm_mode_t loa_mode;

	int loa_fd;
	bool loa_readonly;

	lofiadm_error_t loa_error;

	uint_t loa_maxminor;
	uint_t loa_minor;

	ilstr_t loa_path_blk;
	ilstr_t loa_path_raw;
	ilstr_t loa_filename;
	ilstr_t loa_compression;
	bool loa_ent_readonly;
	bool loa_ent_label;
	bool loa_ent_encrypted;
};

lofiadm_error_t
lofiadm_init(lofiadm_t **loap, uint_t flags)
{
	const char *lofictl = "/dev/" LOFI_CTL_NAME;
	lofiadm_t *loa = NULL;
	int oflags;

	if ((flags & ~LOFIADM_F_VALID) != 0) {
		return (LOFIADM_ERR_INVALID_FLAGS);
	}

	if ((loa = calloc(1, sizeof (*loa))) == NULL) {
		*loap = NULL;
		return (LOFIADM_ERR_MEMORY_ALLOC);
	}
	loa->loa_mode = LOFIADM_MODE_REST;

	if (flags & LOFIADM_F_READWRITE) {
		oflags = O_RDWR;
		loa->loa_readonly = false;
	} else {
		oflags = O_RDONLY;
		loa->loa_readonly = true;
	}

	if ((loa->loa_fd = open(lofictl, oflags)) < 0) {
		free(loa);
		*loap = NULL;

		switch (errno) {
		case EACCES:
		case EPERM:
			return (LOFIADM_ERR_ACCESS);
		default:
			return (LOFIADM_ERR_DEVICE);
		}
	}

	ilstr_init(&loa->loa_path_blk, 0);
	ilstr_init(&loa->loa_path_raw, 0);
	ilstr_init(&loa->loa_filename, 0);

	*loap = loa;
	return (0);
}

void
lofiadm_fini(lofiadm_t *loa)
{
	if (loa == NULL) {
		return;
	}

	ilstr_fini(&loa->loa_path_blk);
	ilstr_fini(&loa->loa_path_raw);
	(void) close(loa->loa_fd);
	free(loa);
}

static bool
lookup_minor(const char *path, uint_t *id)
{
	struct stat st;

	if (stat(path, &st) != 0 ||
	    (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))) {
		/*
		 * This path does not exist, or is not a device.
		 */
		return (false);
	}

	major_t maj = major(st.st_rdev);
	char driver[MODMAXNAMELEN];

	if (modctl(MODGETNAME, driver, sizeof (driver), &maj) != 0 ||
	    strcmp(driver, LOFI_DRIVER_NAME) != 0) {
		return (false);
	}

	*id = LOFI_MINOR2ID(minor(st.st_rdev));
	return (true);
}

static void
pathforminor(ilstr_t *ils, const char *devdir, uint_t id)
{
	ilstr_reset(ils);

	ilstr_append_str(ils, "/dev/");
	ilstr_append_str(ils, devdir);
	ilstr_append_str(ils, "/");
	ilstr_append_uint(ils, id);

	if (ilstr_errno(ils) != ILSTR_ERROR_OK) {
		ilstr_reset(ils);
	}
}

static void
copy_string(ilstr_t *ils, const char *input, bool question_mark)
{
	ilstr_reset(ils);

	if (question_mark && strcmp(input, "?") == 0) {
		/*
		 * This sentinel is used by the kernel under some conditions
		 * when it cannot reconstruct the file name for a lofi device.
		 */
		return;
	}

	ilstr_append_str(ils, input);

	if (ilstr_errno(ils) != ILSTR_ERROR_OK) {
		ilstr_reset(ils);
	}
}

static void
finishpath(ilstr_t *ils, bool label)
{
	if (label && ilstr_len(ils) > 0) {
		ilstr_append_str(ils, "p0");
	}

	if (ilstr_errno(ils) != ILSTR_ERROR_OK) {
		ilstr_reset(ils);
	}
}

static void
lofiadm_save_result(lofiadm_t *loa, struct lofi_ioctl *li)
{
	ilstr_reset(&loa->loa_path_blk);
	ilstr_reset(&loa->loa_path_raw);

	if (li->li_devpath[0] == '\0') {
		/*
		 * If the kernel did not tell us what the path is, and this is
		 * not a device with a label, we can make a guess based on the
		 * minor number.
		 */
		if (!li->li_labeled) {
			pathforminor(&loa->loa_path_blk, LOFI_BLOCK_NAME,
			    li->li_id);
			pathforminor(&loa->loa_path_raw, LOFI_CHAR_NAME,
			    li->li_id);
		}
	} else {
		/*
		 * The device path we get back from the kernel is the
		 * raw/character path.  For devices with and without a label,
		 * we can get the block device path by removing the first "r"
		 * in the path.
		 */
		const char *r = strchr(li->li_devpath, 'r');
		if (r != NULL) {
			ilstr_append_strn(&loa->loa_path_blk, li->li_devpath,
			    r - li->li_devpath);
			ilstr_append_str(&loa->loa_path_blk, r + 1);
		}
		finishpath(&loa->loa_path_blk, li->li_labeled);

		/*
		 * The raw/character path we can use as-is:
		 */
		ilstr_append_str(&loa->loa_path_raw, li->li_devpath);
		finishpath(&loa->loa_path_raw, li->li_labeled);
	}

	copy_string(&loa->loa_filename, li->li_filename, true);
	copy_string(&loa->loa_compression, li->li_algorithm, false);

	loa->loa_ent_readonly = li->li_readonly != B_FALSE;
	loa->loa_ent_label = li->li_labeled != B_FALSE;
	loa->loa_ent_encrypted = li->li_crypto_enabled != B_FALSE;
}

bool
lofiadm_lookup_file(lofiadm_t *loa, const char *path)
{
	struct lofi_ioctl li;

	lofiadm_reset(loa);

	bzero(&li, sizeof (li));
	if (strlcpy(li.li_filename, path, sizeof (li.li_filename)) >=
	    sizeof (li.li_filename)) {
		loa->loa_error = LOFIADM_ERR_PATH_TOO_LONG;
		return (false);
	}

	if (ioctl(loa->loa_fd, LOFI_GET_MINOR, &li) != 0) {
		loa->loa_error = LOFIADM_ERR_NO_FILE_MATCH;
		return (false);
	}

	loa->loa_mode = LOFIADM_MODE_LOOKUP;
	lofiadm_save_result(loa, &li);

	return (true);
}

bool
lofiadm_lookup_device(lofiadm_t *loa, const char *path)
{
	struct lofi_ioctl li;

	lofiadm_reset(loa);

	bzero(&li, sizeof (li));
	if (!lookup_minor(path, &li.li_id)) {
		loa->loa_error = LOFIADM_ERR_NO_DEVICE_MATCH;
		return (false);
	}

	if (ioctl(loa->loa_fd, LOFI_GET_FILENAME, &li) != 0) {
		loa->loa_error = LOFIADM_ERR_NO_DEVICE_MATCH;
		return (false);
	}

	loa->loa_mode = LOFIADM_MODE_LOOKUP;
	lofiadm_save_result(loa, &li);

	return (true);
}

lofiadm_error_t
lofiadm_error(lofiadm_t *loa)
{
	return (loa->loa_error);
}

const char *
lofiadm_strerror(lofiadm_error_t e)
{
	switch (e) {
	case LOFIADM_ERR_OK:
		return ("no error");
	case LOFIADM_ERR_INVALID_FLAGS:
		return ("invalid flags");
	case LOFIADM_ERR_MEMORY_ALLOC:
		return ("failed to allocate memory");
	case LOFIADM_ERR_READONLY:
		return ("read-write operation attempted on read-only handle");
	case LOFIADM_ERR_ACCESS:
		return ("permission denied");
	case LOFIADM_ERR_DEVICE:
		return ("could not open lofi control device");
	case LOFIADM_ERR_INTERNAL:
		return ("internal error");
	case LOFIADM_ERR_PATH_TOO_LONG:
		return ("supplied path is too long");
	case LOFIADM_ERR_NO_FILE_MATCH:
		return ("no single lofi device matches the supplied file name");
	case LOFIADM_ERR_NO_DEVICE_MATCH:
		return ("no single lofi device matches the supplied device "
		    "path");
	case LOFIADM_ERR_NOT_WALKING:
		return ("must call lofiadm_walk() before lofiadm_walk_next()");
	}

	return ("unknown");
}

void
lofiadm_reset(lofiadm_t *loa)
{
	loa->loa_mode = LOFIADM_MODE_REST;
	loa->loa_minor = 0;
	loa->loa_maxminor = 0;
	loa->loa_error = 0;
	ilstr_reset(&loa->loa_path_blk);
	ilstr_reset(&loa->loa_path_raw);
}

bool
lofiadm_walk(lofiadm_t *loa)
{
	struct lofi_ioctl li;

	lofiadm_reset(loa);

	li.li_id = 0;
	if (ioctl(loa->loa_fd, LOFI_GET_MAXMINOR, &li) != 0) {
		loa->loa_error = LOFIADM_ERR_INTERNAL;
		return (false);
	}
	loa->loa_mode = LOFIADM_MODE_WALK;
	loa->loa_maxminor = li.li_id;
	loa->loa_minor = 0;
	return (true);
}

bool
lofiadm_walk_next(lofiadm_t *loa)
{
	if (loa->loa_error != LOFIADM_ERR_OK) {
		return (false);
	}

	if (loa->loa_mode != LOFIADM_MODE_WALK) {
		loa->loa_error = LOFIADM_ERR_NOT_WALKING;
		return (false);
	}

again:
	if (loa->loa_minor >= loa->loa_maxminor) {
		return (false);
	}
	loa->loa_minor++;

	struct lofi_ioctl li;
	bzero(&li, sizeof (li));
	li.li_id = loa->loa_minor;
	if (ioctl(loa->loa_fd, LOFI_GET_FILENAME, &li) != 0) {
		if (errno == ENXIO) {
			/*
			 * This minor number is not in use.  Skip straight to
			 * the next one.
			 */
			goto again;
		}

		/*
		 * This ioctl should generally only fail due to programming
		 * errors on our part.
		 */
		loa->loa_error = LOFIADM_ERR_INTERNAL;
		return (false);
	}

	lofiadm_save_result(loa, &li);

	return (true);
}

bool
entok(lofiadm_t *loa)
{
	return (loa->loa_error == LOFIADM_ERR_OK &&
	    loa->loa_mode != LOFIADM_MODE_REST);
}

bool
lofiadm_ent_readonly(lofiadm_t *loa)
{
	if (!entok(loa)) {
		return (false);
	}

	return (loa->loa_ent_readonly);
}

bool
lofiadm_ent_label(lofiadm_t *loa)
{
	if (!entok(loa)) {
		return (false);
	}

	return (loa->loa_ent_label);
}

bool
lofiadm_ent_encrypted(lofiadm_t *loa)
{
	if (!entok(loa)) {
		return (false);
	}

	return (loa->loa_ent_encrypted);
}

bool
lofiadm_ent_compressed(lofiadm_t *loa)
{
	if (!entok(loa)) {
		return (false);
	}

	return (ilstr_len(&loa->loa_compression) > 0);
}

static const char *
no_empty_string(ilstr_t *ils)
{
	if (ilstr_len(ils) == 0) {
		return (NULL);
	} else {
		return (ilstr_cstr(ils));
	}
}

const char *
lofiadm_ent_filename(lofiadm_t *loa)
{
	if (!entok(loa)) {
		return (NULL);
	}

	return (no_empty_string(&loa->loa_filename));
}

const char *
lofiadm_ent_compression(lofiadm_t *loa)
{
	if (!entok(loa)) {
		return (NULL);
	}

	return (no_empty_string(&loa->loa_compression));
}

const char *
lofiadm_ent_rdevpath(lofiadm_t *loa)
{
	if (!entok(loa)) {
		return (NULL);
	}

	return (no_empty_string(&loa->loa_path_raw));
}

const char *
lofiadm_ent_devpath(lofiadm_t *loa)
{
	if (!entok(loa)) {
		return (NULL);
	}

	return (no_empty_string(&loa->loa_path_blk));
}

int
lofiadm_fd(lofiadm_t *loa)
{
	return (loa->loa_fd);
}
