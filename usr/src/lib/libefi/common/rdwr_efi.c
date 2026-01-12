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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2014 Toomas Soome <tsoome@me.com>
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2022 Jason King
 * Copyright 2024 MNX Cloud, Inc.
 * Copyright 2025 Oxide Computer Company
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <smbios.h>
#include <uuid/uuid.h>
#include <libintl.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/mhd.h>
#include <sys/param.h>
#include <sys/dktp/fdisk.h>
#include <sys/efi_partition.h>
#include <sys/byteorder.h>
#include <sys/ddi.h>
#include <sys/sysmacros.h>
#include <sys/ilstr.h>
#include <vec.h>

typedef struct dk_check_msg {
	uint_t			dkm_partition;
	bool			dkm_error;
	ilstr_t			dkm_msg;
} dk_check_msg_t;

struct dk_check {
	vec_t			*dkc_msgs;
	bool			dkc_failed;
	int			dkc_resv_part;
};

/*
 * The original conversion array used simple array index, but since
 * we do need to take account of VTOC tag numbers from other systems,
 * we need to provide tag values too, or the array will grow too large.
 *
 * Still we will fabricate the missing p_tag values.
 */
static struct uuid_to_ptag {
	struct uuid		uuid;
	ushort_t		p_tag;
} conversions[] = {
	{ EFI_UNUSED,		V_UNASSIGNED },
	{ EFI_BOOT,		V_BOOT },
	{ EFI_ROOT,		V_ROOT },
	{ EFI_SWAP,		V_SWAP },
	{ EFI_USR,		V_USR },
	{ EFI_BACKUP,		V_BACKUP },
	{ EFI_VAR,		V_VAR },
	{ EFI_HOME,		V_HOME },
	{ EFI_ALTSCTR,		V_ALTSCTR },
	{ EFI_RESERVED,		V_RESERVED },
	{ EFI_SYSTEM,		V_SYSTEM },
	{ EFI_LEGACY_MBR,	V_LEGACY_MBR },
	{ EFI_SYMC_PUB,		V_SYMC_PUB },
	{ EFI_SYMC_CDS,		V_SYMC_CDS },
	{ EFI_MSFT_RESV,	V_MSFT_RESV },
	{ EFI_DELL_BASIC,	V_DELL_BASIC },
	{ EFI_DELL_RAID,	V_DELL_RAID },
	{ EFI_DELL_SWAP,	V_DELL_SWAP },
	{ EFI_DELL_LVM,		V_DELL_LVM },
	{ EFI_DELL_RESV,	V_DELL_RESV },
	{ EFI_AAPL_HFS,		V_AAPL_HFS },
	{ EFI_AAPL_UFS,		V_AAPL_UFS },
	{ EFI_AAPL_ZFS,		V_AAPL_ZFS },
	{ EFI_AAPL_APFS,	V_AAPL_APFS },
	{ EFI_BIOS_BOOT,	V_BIOS_BOOT },
	{ EFI_FREEBSD_BOOT,	V_FREEBSD_BOOT },
	{ EFI_FREEBSD_SWAP,	V_FREEBSD_SWAP },
	{ EFI_FREEBSD_UFS,	V_FREEBSD_UFS },
	{ EFI_FREEBSD_VINUM,	V_FREEBSD_VINUM },
	{ EFI_FREEBSD_ZFS,	V_FREEBSD_ZFS },
	{ EFI_FREEBSD_NANDFS,	V_FREEBSD_NANDFS }
};

#define	NCONVERSIONS	ARRAY_SIZE(conversions)

/*
 * Default VTOC tags for EFI partition tables created by rmformat(1):
 */
struct dk_map2 default_vtoc_map_rmformat[NDKMAP] = {
	{ V_ROOT,		0	},		/* a - 0 */
	{ V_SWAP,		V_UNMNT	},		/* b - 1 */
	{ V_UNASSIGNED,		V_UNMNT	},		/* c - 2 */
	{ V_UNASSIGNED,		0	},		/* d - 3 */
	{ V_UNASSIGNED,		0	},		/* e - 4 */
	{ V_UNASSIGNED,		0	},		/* f - 5 */
	{ V_USR,		0	},		/* g - 6 */
	{ V_UNASSIGNED,		0	},		/* h - 7 */
	{ V_BOOT,		V_UNMNT	},		/* i - 8 */
	{ V_ALTSCTR,		0	},		/* j - 9 */
	{ V_UNASSIGNED,		0	},		/* k - 10 */
	{ V_UNASSIGNED,		0	},		/* l - 11 */
	{ V_UNASSIGNED,		0	},		/* m - 12 */
	{ V_UNASSIGNED,		0	},		/* n - 13 */
	{ V_UNASSIGNED,		0	},		/* o - 14 */
	{ V_UNASSIGNED,		0	},		/* p - 15 */
};

#ifdef DEBUG
int efi_debug = 1;
#else
int efi_debug = 0;
#endif
boolean_t efi_debug_env_checked = B_FALSE;

#define	EFI_FIXES_DB "/usr/share/hwdata/efi.fixes"

extern unsigned int efi_crc32(const unsigned char *, unsigned int);
static int efi_read(int, struct dk_gpt *);
static void efi_debugf(const char *, ...) __PRINTFLIKE(1);


static void
efi_debugf(const char *format, ...)
{
	char buf[LINE_MAX];
	va_list ap;

	if (efi_debug == 0 && !efi_debug_env_checked) {
		efi_debug_env_checked = B_TRUE;

		char *val = getenv("EFI_DEBUG");
		if (val != NULL && *val != '\0') {
			efi_debug = 1;
		}
	}

	if (efi_debug == 0) {
		return;
	}

	va_start(ap, format);
	(void) vsnprintf(buf, sizeof (buf), format, ap);
	va_end(ap);

	(void) fprintf(stderr, "libefi: %s\n", buf);
}

static int
read_disk_info(int fd, diskaddr_t *capacity, uint_t *lbsize)
{
	struct dk_minfo disk_info;

	if ((ioctl(fd, DKIOCGMEDIAINFO, (caddr_t)&disk_info)) == -1)
		return (errno);
	*capacity = disk_info.dki_capacity;
	*lbsize = disk_info.dki_lbsize;
	return (0);
}

/*
 * the number of blocks the EFI label takes up (round up to nearest
 * block)
 */
#define	NBLOCKS(p, l)	(1 + ((((p) * (int)sizeof (efi_gpe_t))  + \
				((l) - 1)) / (l)))
/* number of partitions -- limited by what we can malloc */
#define	MAX_PARTS	((4294967295UL - sizeof (struct dk_gpt)) / \
			    sizeof (struct dk_part))

/*
 * Return the highest LBA covered by this partition.
 */
static diskaddr_t
part_end(struct dk_part *part)
{
	return (part->p_start + part->p_size - 1);
}

static struct dk_part *
partn(struct dk_gpt *vtoc, uint_t n)
{
	if (n >= vtoc->efi_nparts) {
		return (NULL);
	}

	return (&vtoc->efi_parts[n]);
}

/*
 * The EFI reserved partition size is 8 MiB. This calculates the number of
 * sectors required to store 8 MiB, taking into account the device's sector
 * size.
 */
uint_t
efi_reserved_sectors(dk_gpt_t *efi)
{
	/* roundup to sector size */
	return ((EFI_MIN_RESV_SIZE * DEV_BSIZE + efi->efi_lbasize - 1) /
	    efi->efi_lbasize);
}

int
efi_alloc_and_init(int fd, uint32_t nparts, struct dk_gpt **vtoc)
{
	diskaddr_t capacity;
	uint_t lbsize;
	uint_t nblocks;
	size_t length;
	struct dk_gpt *vptr;
	struct uuid uuid;

	if (read_disk_info(fd, &capacity, &lbsize) != 0) {
		efi_debugf("couldn't read disk information");
		return (-1);
	}

	nblocks = NBLOCKS(nparts, lbsize);
	if ((nblocks * lbsize) < EFI_MIN_ARRAY_SIZE + lbsize) {
		/* 16K plus one block for the GPT */
		nblocks = EFI_MIN_ARRAY_SIZE / lbsize + 1;
	}

	if (nparts > MAX_PARTS) {
		efi_debugf("the maximum number of partitions supported "
		    "is %lu\n", MAX_PARTS);
		return (-1);
	}

	length = sizeof (struct dk_gpt) +
	    sizeof (struct dk_part) * (nparts - 1);

	if ((*vtoc = calloc(1, length)) == NULL)
		return (-1);

	vptr = *vtoc;

	vptr->efi_version = EFI_VERSION_CURRENT;
	vptr->efi_lbasize = lbsize;
	vptr->efi_nparts = nparts;
	/*
	 * add one block here for the PMBR; on disks with a 512 byte
	 * block size and 128 or fewer partitions, efi_first_u_lba
	 * should work out to "34"
	 */
	vptr->efi_first_u_lba = nblocks + 1;
	vptr->efi_last_lba = capacity - 1;
	vptr->efi_altern_lba = capacity - 1;
	vptr->efi_last_u_lba = vptr->efi_last_lba - nblocks;

	(void) uuid_generate((uchar_t *)&uuid);
	UUID_LE_CONVERT(vptr->efi_disk_uguid, uuid);
	return (0);
}

/*
 * Read EFI - return partition number upon success.
 */
int
efi_alloc_and_read(int fd, struct dk_gpt **vtoc)
{
	int rval;
	uint32_t nparts;
	int length;
	struct mboot *mbr;
	struct ipart *ipart;
	diskaddr_t capacity;
	uint_t lbsize;
	int i;

	if (read_disk_info(fd, &capacity, &lbsize) != 0)
		return (VT_ERROR);

	if ((mbr = calloc(1, lbsize)) == NULL)
		return (VT_ERROR);

	if ((ioctl(fd, DKIOCGMBOOT, (caddr_t)mbr)) == -1) {
		free(mbr);
		return (VT_ERROR);
	}

	if (mbr->signature != MBB_MAGIC) {
		free(mbr);
		return (VT_EINVAL);
	}
	ipart = (struct ipart *)(uintptr_t)mbr->parts;

	/* Check if we have partition with ID EFI_PMBR */
	for (i = 0; i < FD_NUMPART; i++) {
		if (ipart[i].systid == EFI_PMBR)
			break;
	}
	free(mbr);
	if (i == FD_NUMPART)
		return (VT_EINVAL);

	/* figure out the number of entries that would fit into 16K */
	nparts = EFI_MIN_ARRAY_SIZE / sizeof (efi_gpe_t);
	length = (int) sizeof (struct dk_gpt) +
	    (int) sizeof (struct dk_part) * (nparts - 1);
	if ((*vtoc = calloc(1, length)) == NULL)
		return (VT_ERROR);

	(*vtoc)->efi_nparts = nparts;
	rval = efi_read(fd, *vtoc);

	if (rval == VT_EINVAL && (*vtoc)->efi_nparts > nparts) {
		void *tmp;
		length = (int) sizeof (struct dk_gpt) +
		    (int) sizeof (struct dk_part) *
		    ((*vtoc)->efi_nparts - 1);
		nparts = (*vtoc)->efi_nparts;
		if ((tmp = realloc(*vtoc, length)) == NULL) {
			free(*vtoc);
			*vtoc = NULL;
			return (VT_ERROR);
		} else {
			*vtoc = tmp;
			rval = efi_read(fd, *vtoc);
		}
	}

	if (rval < 0) {
		efi_debugf("read of EFI table failed, rval=%d", rval);
		free(*vtoc);
		*vtoc = NULL;
	}

	return (rval);
}

static int
efi_ioctl(int fd, int cmd, dk_efi_t *dk_ioc)
{
	void *data = dk_ioc->dki_data;
	int error;

	dk_ioc->dki_data_64 = (uint64_t)(uintptr_t)data;
	error = ioctl(fd, cmd, (void *)dk_ioc);
	dk_ioc->dki_data = data;

	return (error);
}


int
efi_check_ok(const dk_check_t *dkc)
{
	if (dkc == NULL || dkc->dkc_failed) {
		return (0);
	}

	for (uint_t i = 0; i < efi_check_nmsg(dkc); i++) {
		if (efi_check_msg_is_error(dkc, i)) {
			return (0);
		}
	}

	return (1);
}

uint_t
efi_check_nmsg(const dk_check_t *dkc)
{
	return (vec_len(dkc->dkc_msgs));
}

int
efi_check_msg_is_error(const dk_check_t *dkc, uint_t n)
{
	if (n >= vec_len(dkc->dkc_msgs)) {
		return (0);
	}

	dk_check_msg_t *dkm = vec_get(dkc->dkc_msgs, n);

	return (dkm->dkm_error == true);
}

const char *
efi_check_msg(const dk_check_t *dkc, uint_t n)
{
	if (n >= vec_len(dkc->dkc_msgs)) {
		return (NULL);
	}

	dk_check_msg_t *dkm = vec_get(dkc->dkc_msgs, n);
	return (ilstr_cstr(&dkm->dkm_msg));
}

static void
efi_dkm_free(dk_check_msg_t *dkm)
{
	if (dkm == NULL) {
		return;
	}

	ilstr_fini(&dkm->dkm_msg);
	free(dkm);
}

void
efi_check_free(dk_check_t *dkc)
{
	if (dkc == NULL) {
		return;
	}

	dk_check_msg_t *dkm;
	while ((dkm = vec_pop(dkc->dkc_msgs)) != NULL) {
		efi_dkm_free(dkm);
	}
	vec_free(dkc->dkc_msgs);

	free(dkc);
}

static dk_check_t *
efi_check_alloc(void)
{
	dk_check_t *dkc = malloc(sizeof (*dkc));
	if (dkc == NULL || (dkc->dkc_msgs = vec_alloc()) == NULL) {
		free(dkc);
		return (NULL);
	}

	dkc->dkc_failed = false;
	dkc->dkc_resv_part = -1;

	return (dkc);
}

dk_check_t *
efi_check(struct dk_gpt *vtoc)
{
	/*
	 * XXX
	 */
	return (NULL);
}

#define	MISC	UINT_MAX

static void
efi_checkf_add(dk_check_t *dkc, uint_t part, bool error, const char *fmt, ...)
{
	va_list ap;

	dk_check_msg_t *dkm = calloc(1, sizeof (*dkm));
	if (dkm == NULL) {
		goto bail;
	}
	ilstr_init(&dkm->dkm_msg, 0);
	dkm->dkm_partition = part;
	dkm->dkm_error = error;

	va_start(ap, fmt);
	ilstr_vaprintf(&dkm->dkm_msg, fmt, ap);
	va_end(ap);

	if (ilstr_errno(&dkm->dkm_msg) != ILSTR_ERROR_OK) {
		goto bail;
	}

	const char *level = error ? "error" : "warning";
	if (part != MISC) {
		efi_debugf("check: %s: partition %u: %s", level, part, 
		    ilstr_cstr(&dkm->dkm_msg));

		ilstr_pprintf(&dkm->dkm_msg, "Partition %u ", part);
	} else {
		efi_debugf("check: %s: %s", level, ilstr_cstr(&dkm->dkm_msg));
	}

	if (vec_push(dkc->dkc_msgs, dkm) != 0) {
		goto bail;
	}

	return;

bail:
	dkc->dkc_failed = true;
	efi_dkm_free(dkm);
}

static int
check_label(int fd, dk_efi_t *dk_ioc)
{
	efi_gpt_t *efi;
	uint_t crc;

	if (efi_ioctl(fd, DKIOCGETEFI, dk_ioc) == -1) {
		switch (errno) {
		case EIO:
			return (VT_EIO);
		default:
			return (VT_ERROR);
		}
	}
	efi = dk_ioc->dki_data;
	if (efi->efi_gpt_Signature != LE_64(EFI_SIGNATURE)) {
		efi_debugf("Bad EFI signature: 0x%llx != 0x%llx",
		    (long long)efi->efi_gpt_Signature,
		    (long long)LE_64(EFI_SIGNATURE));
		return (VT_EINVAL);
	}

	/*
	 * check CRC of the header; the size of the header should
	 * never be larger than one block
	 */
	crc = efi->efi_gpt_HeaderCRC32;
	efi->efi_gpt_HeaderCRC32 = 0;

	if (((len_t)LE_32(efi->efi_gpt_HeaderSize) > dk_ioc->dki_length) ||
	    crc != LE_32(efi_crc32((unsigned char *)efi,
	    LE_32(efi->efi_gpt_HeaderSize)))) {
		efi_debugf("Bad EFI CRC: 0x%x != 0x%x",
		    crc, LE_32(efi_crc32((unsigned char *)efi,
		    LE_32(efi->efi_gpt_HeaderSize))));
		return (VT_EINVAL);
	}

	return (0);
}

static int
efi_read(int fd, struct dk_gpt *vtoc)
{
	int i, j;
	int label_len;
	int rval = 0;
	int vdc_flag = 0;
	struct dk_minfo disk_info;
	dk_efi_t dk_ioc;
	efi_gpt_t *efi;
	efi_gpe_t *efi_parts;
	struct dk_cinfo dki_info;
	uint32_t user_length;
	boolean_t legacy_label = B_FALSE;

	/*
	 * get the partition number for this file descriptor.
	 */
	if (ioctl(fd, DKIOCINFO, (caddr_t)&dki_info) == -1) {
		efi_debugf("DKIOCINFO errno 0x%x", errno);
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		default:
			return (VT_ERROR);
		}
	}

	if ((strncmp(dki_info.dki_cname, "vdc", 4) == 0) &&
	    (strncmp(dki_info.dki_dname, "vdc", 4) == 0)) {
		/*
		 * The controller and drive name "vdc" (virtual disk client)
		 * indicates a LDoms virtual disk.
		 */
		vdc_flag++;
	}

	/* get the LBA size */
	if (ioctl(fd, DKIOCGMEDIAINFO, (caddr_t)&disk_info) == -1) {
		efi_debugf("assuming LBA 512 bytes %d", errno);
		disk_info.dki_lbsize = DEV_BSIZE;
	}
	if (disk_info.dki_lbsize == 0) {
		efi_debugf("efi_read: assuming LBA 512 bytes");
		disk_info.dki_lbsize = DEV_BSIZE;
	}
	/*
	 * Read the EFI GPT to figure out how many partitions we need
	 * to deal with.
	 */
	dk_ioc.dki_lba = 1;
	if (NBLOCKS(vtoc->efi_nparts, disk_info.dki_lbsize) < 34) {
		label_len = EFI_MIN_ARRAY_SIZE + disk_info.dki_lbsize;
	} else {
		label_len = vtoc->efi_nparts * (int) sizeof (efi_gpe_t) +
		    disk_info.dki_lbsize;
		if (label_len % disk_info.dki_lbsize) {
			/* pad to physical sector size */
			label_len += disk_info.dki_lbsize;
			label_len &= ~(disk_info.dki_lbsize - 1);
		}
	}

	if ((dk_ioc.dki_data = calloc(1, label_len)) == NULL)
		return (VT_ERROR);

	dk_ioc.dki_length = disk_info.dki_lbsize;
	user_length = vtoc->efi_nparts;
	efi = dk_ioc.dki_data;
	if ((rval = check_label(fd, &dk_ioc)) == VT_EINVAL) {
		/*
		 * No valid label here; try the alternate. Note that here
		 * we just read GPT header and save it into dk_ioc.data,
		 * Later, we will read GUID partition entry array if we
		 * can get valid GPT header.
		 */

		/*
		 * This is a workaround for legacy systems. In the past, the
		 * last sector of SCSI disk was invisible on x86 platform. At
		 * that time, backup label was saved on the next to the last
		 * sector. It is possible for users to move a disk from previous
		 * solaris system to present system. Here, we attempt to search
		 * legacy backup EFI label first.
		 */
		dk_ioc.dki_lba = disk_info.dki_capacity - 2;
		dk_ioc.dki_length = disk_info.dki_lbsize;
		rval = check_label(fd, &dk_ioc);
		if (rval == VT_EINVAL) {
			/*
			 * we didn't find legacy backup EFI label, try to
			 * search backup EFI label in the last block.
			 */
			dk_ioc.dki_lba = disk_info.dki_capacity - 1;
			dk_ioc.dki_length = disk_info.dki_lbsize;
			rval = check_label(fd, &dk_ioc);
			if (rval == 0) {
				legacy_label = B_TRUE;
				efi_debugf("efi_read: primary label corrupt; "
				    "using EFI backup label located on the "
				    "last block");
			}
		} else if (rval == 0) {
			efi_debugf("efi_read: primary label "
			    "corrupt; using legacy EFI backup label "
			    "located on the next to last block");
		}

		if (rval == 0) {
			dk_ioc.dki_lba = LE_64(efi->efi_gpt_PartitionEntryLBA);
			vtoc->efi_flags |= EFI_GPT_PRIMARY_CORRUPT;
			vtoc->efi_nparts =
			    LE_32(efi->efi_gpt_NumberOfPartitionEntries);
			/*
			 * Partition tables are between backup GPT header
			 * table and ParitionEntryLBA (the starting LBA of
			 * the GUID partition entries array). Now that we
			 * already got valid GPT header and saved it in
			 * dk_ioc.dki_data, we try to get GUID partition
			 * entry array here.
			 */
			dk_ioc.dki_data = (efi_gpt_t *)((char *)dk_ioc.dki_data
			    + disk_info.dki_lbsize);
			if (legacy_label) {
				dk_ioc.dki_length = disk_info.dki_capacity - 1 -
				    dk_ioc.dki_lba;
			} else {
				dk_ioc.dki_length = disk_info.dki_capacity - 2 -
				    dk_ioc.dki_lba;
			}
			dk_ioc.dki_length *= disk_info.dki_lbsize;
			if (dk_ioc.dki_length >
			    ((len_t)label_len - sizeof (*dk_ioc.dki_data))) {
				rval = VT_EINVAL;
			} else {
				/*
				 * read GUID partition entry array
				 */
				rval = efi_ioctl(fd, DKIOCGETEFI, &dk_ioc);
			}
		}

	} else if (rval == 0) {
		dk_ioc.dki_lba = LE_64(efi->efi_gpt_PartitionEntryLBA);
		dk_ioc.dki_data = (efi_gpt_t *)((char *)dk_ioc.dki_data
		    + disk_info.dki_lbsize);
		dk_ioc.dki_length = label_len - disk_info.dki_lbsize;
		rval = efi_ioctl(fd, DKIOCGETEFI, &dk_ioc);

	} else if (vdc_flag && rval == VT_ERROR && errno == EINVAL) {
		/*
		 * When the device is a LDoms virtual disk, the DKIOCGETEFI
		 * ioctl can fail with EINVAL if the virtual disk backend
		 * is a ZFS volume serviced by a domain running an old version
		 * of Solaris. This is because the DKIOCGETEFI ioctl was
		 * initially incorrectly implemented for a ZFS volume and it
		 * expected the GPT and GPE to be retrieved with a single ioctl.
		 * So we try to read the GPT and the GPE using that old style
		 * ioctl.
		 */
		dk_ioc.dki_lba = 1;
		dk_ioc.dki_length = label_len;
		rval = check_label(fd, &dk_ioc);
	}

	if (rval < 0) {
		free(efi);
		return (rval);
	}

	efi_parts = (efi_gpe_t *)(((char *)efi) + disk_info.dki_lbsize);

	/*
	 * Assemble this into a "dk_gpt" struct for easier
	 * digestibility by applications.
	 */
	vtoc->efi_version = LE_32(efi->efi_gpt_Revision);
	vtoc->efi_nparts = LE_32(efi->efi_gpt_NumberOfPartitionEntries);
	vtoc->efi_part_size = LE_32(efi->efi_gpt_SizeOfPartitionEntry);
	vtoc->efi_lbasize = disk_info.dki_lbsize;
	vtoc->efi_last_lba = disk_info.dki_capacity - 1;
	vtoc->efi_first_u_lba = LE_64(efi->efi_gpt_FirstUsableLBA);
	vtoc->efi_last_u_lba = LE_64(efi->efi_gpt_LastUsableLBA);
	vtoc->efi_altern_lba = LE_64(efi->efi_gpt_AlternateLBA);
	UUID_LE_CONVERT(vtoc->efi_disk_uguid, efi->efi_gpt_DiskGUID);

	/*
	 * If the array the user passed in is too small, set the length
	 * to what it needs to be and return
	 */
	if (user_length < vtoc->efi_nparts) {
		return (VT_EINVAL);
	}

	for (i = 0; i < vtoc->efi_nparts; i++) {
		UUID_LE_CONVERT(vtoc->efi_parts[i].p_guid,
		    efi_parts[i].efi_gpe_PartitionTypeGUID);

		for (j = 0; j < NCONVERSIONS; j++) {
			if (bcmp(&vtoc->efi_parts[i].p_guid,
			    &conversions[j].uuid,
			    sizeof (struct uuid)) == 0) {
				vtoc->efi_parts[i].p_tag =
				    conversions[j].p_tag;
				break;
			}
		}
		if (vtoc->efi_parts[i].p_tag == V_UNASSIGNED)
			continue;
		vtoc->efi_parts[i].p_flag =
		    LE_16(efi_parts[i].efi_gpe_Attributes.PartitionAttrs);
		vtoc->efi_parts[i].p_start =
		    LE_64(efi_parts[i].efi_gpe_StartingLBA);
		vtoc->efi_parts[i].p_size =
		    LE_64(efi_parts[i].efi_gpe_EndingLBA) -
		    vtoc->efi_parts[i].p_start + 1;
		for (j = 0; j < EFI_PART_NAME_LEN; j++) {
			vtoc->efi_parts[i].p_name[j] =
			    (uchar_t)LE_16(
			    efi_parts[i].efi_gpe_PartitionName[j]);
		}

		UUID_LE_CONVERT(vtoc->efi_parts[i].p_uguid,
		    efi_parts[i].efi_gpe_UniquePartitionGUID);
	}
	free(efi);

	return (dki_info.dki_partition);
}

static void
hardware_workarounds(int *slot, int *active)
{
	smbios_struct_t s_sys, s_mb;
	smbios_info_t sys, mb;
	smbios_hdl_t *shp;
	char buf[0x400];
	FILE *fp;
	int err;

	if ((fp = fopen(EFI_FIXES_DB, "rF")) == NULL)
		return;

	if ((shp = smbios_open(NULL, SMB_VERSION, 0, &err)) == NULL) {
		efi_debugf("failed to load SMBIOS: %s", smbios_errmsg(err));
		(void) fclose(fp);
		return;
	}

	if (smbios_lookup_type(shp, SMB_TYPE_SYSTEM, &s_sys) == SMB_ERR ||
	    smbios_info_common(shp, s_sys.smbstr_id, &sys) == SMB_ERR) {
		(void) memset(&sys, '\0', sizeof (sys));
	}
	if (smbios_lookup_type(shp, SMB_TYPE_BASEBOARD, &s_mb) == SMB_ERR ||
	    smbios_info_common(shp, s_mb.smbstr_id, &mb) == SMB_ERR) {
		(void) memset(&mb, '\0', sizeof (mb));
	}

	while (fgets(buf, sizeof (buf), fp) != NULL) {
		char *tok, *val, *end;

		tok = buf + strspn(buf, " \t");
		if (*tok == '#')
			continue;
		while (*tok != '\0') {
			tok += strspn(tok, " \t");
			if ((val = strchr(tok, '=')) == NULL)
				break;
			*val++ = '\0';
			if (*val == '"')
				end = strchr(++val, '"');
			else
				end = strpbrk(val, " \t\n");
			if (end == NULL)
				break;
			*end++ = '\0';

			if (strcmp(tok, "sys.manufacturer") == 0 &&
			    (sys.smbi_manufacturer == NULL ||
			    strcasecmp(val, sys.smbi_manufacturer))) {
				break;
			}
			if (strcmp(tok, "sys.product") == 0 &&
			    (sys.smbi_product == NULL ||
			    strcasecmp(val, sys.smbi_product))) {
				break;
			}
			if (strcmp(tok, "sys.version") == 0 &&
			    (sys.smbi_version == NULL ||
			    strcasecmp(val, sys.smbi_version))) {
				break;
			}
			if (strcmp(tok, "mb.manufacturer") == 0 &&
			    (mb.smbi_manufacturer == NULL ||
			    strcasecmp(val, mb.smbi_manufacturer))) {
				break;
			}
			if (strcmp(tok, "mb.product") == 0 &&
			    (mb.smbi_product == NULL ||
			    strcasecmp(val, mb.smbi_product))) {
				break;
			}
			if (strcmp(tok, "mb.version") == 0 &&
			    (mb.smbi_version == NULL ||
			    strcasecmp(val, mb.smbi_version))) {
				break;
			}

			if (strcmp(tok, "pmbr_slot") == 0) {
				*slot = atoi(val);
				if (*slot < 0 || *slot > 3)
					*slot = 0;
				efi_debugf("using slot %d", *slot);
			}

			if (strcmp(tok, "pmbr_active") == 0) {
				*active = atoi(val);
				if (*active < 0 || *active > 1)
					*active = 0;
				efi_debugf("using active %d", *active);
			}

			tok = end;
		}
	}
	(void) fclose(fp);
	smbios_close(shp);
}

/* writes a "protective" MBR */
static int
write_pmbr(int fd, struct dk_gpt *vtoc)
{
	dk_efi_t dk_ioc;
	struct mboot mb;
	uchar_t *cp;
	diskaddr_t size_in_lba;
	uchar_t *buf;
	int len, slot, active;

	slot = active = 0;

	hardware_workarounds(&slot, &active);

	len = (vtoc->efi_lbasize == 0) ? sizeof (mb) : vtoc->efi_lbasize;
	buf = calloc(1, len);

	/*
	 * Preserve any boot code and disk signature if the first block is
	 * already an MBR.
	 */
	dk_ioc.dki_lba = 0;
	dk_ioc.dki_length = len;
	dk_ioc.dki_data = (efi_gpt_t *)buf;
	if (efi_ioctl(fd, DKIOCGETEFI, &dk_ioc) == -1) {
		(void) memcpy(&mb, buf, sizeof (mb));
		bzero(&mb, sizeof (mb));
		mb.signature = LE_16(MBB_MAGIC);
	} else {
		(void) memcpy(&mb, buf, sizeof (mb));
		if (mb.signature != LE_16(MBB_MAGIC)) {
			bzero(&mb, sizeof (mb));
			mb.signature = LE_16(MBB_MAGIC);
		}
	}

	bzero(&mb.parts, sizeof (mb.parts));
	cp = (uchar_t *)&mb.parts[slot * sizeof (struct ipart)];
	/* bootable or not */
	*cp++ = active ? ACTIVE : NOTACTIVE;
	/* beginning CHS; same as starting LBA (but one-based) */
	*cp++ = 0x0;
	*cp++ = 0x2;
	*cp++ = 0x0;
	/* OS type */
	*cp++ = EFI_PMBR;
	/* ending CHS; 0xffffff if not representable */
	*cp++ = 0xff;
	*cp++ = 0xff;
	*cp++ = 0xff;
	/* starting LBA: 1 (little endian format) by EFI definition */
	*cp++ = 0x01;
	*cp++ = 0x00;
	*cp++ = 0x00;
	*cp++ = 0x00;
	/* ending LBA: last block on the disk (little endian format) */
	size_in_lba = vtoc->efi_last_lba;
	if (size_in_lba < 0xffffffff) {
		*cp++ = (size_in_lba & 0x000000ff);
		*cp++ = (size_in_lba & 0x0000ff00) >> 8;
		*cp++ = (size_in_lba & 0x00ff0000) >> 16;
		*cp++ = (size_in_lba & 0xff000000) >> 24;
	} else {
		*cp++ = 0xff;
		*cp++ = 0xff;
		*cp++ = 0xff;
		*cp++ = 0xff;
	}

	(void) memcpy(buf, &mb, sizeof (mb));
	dk_ioc.dki_data = (efi_gpt_t *)buf;
	dk_ioc.dki_lba = 0;
	dk_ioc.dki_length = len;
	if (efi_ioctl(fd, DKIOCSETEFI, &dk_ioc) == -1) {
		free(buf);
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		default:
			return (VT_ERROR);
		}
	}
	free(buf);
	return (0);
}

static void
check_input_one(struct dk_gpt *vtoc, struct dk_part *part, uint_t i,
    dk_check_t *dkc)
{
	switch (part->p_tag) {
	case V_UNASSIGNED:
		if (part->p_size != 0) {
			efi_checkf_add(dkc, i, true,
			    "is \"unassigned\" but with size %llu",
			    part->p_size);
			return;
		}

		if (uuid_is_null((uchar_t *)&part->p_guid)) {
			efi_debugf("partition %u: unassigned with no UUID", i);
			return;
		}

		efi_checkf_add(dkc, i, false, "has unknown EFI GUID");
		vtoc->efi_parts[i].p_tag = V_UNKNOWN;
		break;

	case V_RESERVED:
		if (dkc->dkc_resv_part != -1) {
			efi_checkf_add(dkc, i, true,
			    "duplicate reserved partition");
		} else {
			dkc->dkc_resv_part = i;
		}
		break;

	default:
		break;
	}

	if (part->p_start < vtoc->efi_first_u_lba ||
	    part->p_start > vtoc->efi_last_u_lba) {
		efi_checkf_add(dkc, i, true, "starts at %llu, but must be "
		    "between %llu and %llu (inclusive)", part->p_start,
		    vtoc->efi_first_u_lba, vtoc->efi_last_u_lba);
	}

	if (part_end(part) < vtoc->efi_first_u_lba ||
	    part_end(part) > vtoc->efi_last_u_lba) {
		efi_checkf_add(dkc, i, true, "ends at %llu, but must be "
		    "between %llu and %llu (inclusive)", part_end(part),
		    vtoc->efi_first_u_lba, vtoc->efi_last_u_lba);
	}

	if (part->p_size == 0) {
		/*
		 * This partition does not cover any blocks, and thus cannot
		 * overlap with any other partition.
		 */
		return;
	}

	/*
	 * Check for overlapping partitions.  Note that we start the sweep
	 * above the diagnonal in the matrix, so that we do at most one
	 * comparison per pair.
	 */
	for (uint_t other = i + 1; other < vtoc->efi_nparts; other++) {
		diskaddr_t other_start = vtoc->efi_parts[other].p_start;
		diskaddr_t other_end = part_end(&vtoc->efi_parts[other]);

		if (vtoc->efi_parts[other].p_size == 0) {
			/*
			 * The other partition does not cover any blocks, and
			 * thus cannot overlap with this partition.
			 */
			continue;
		}

		if (part->p_start < other_start) {
			if (part_end(part) < other_start) {
				/*
				 * This partition is entirely before the other
				 * partition.
				 */
				continue;
			}
		} else if (part->p_start > other_end) {
			/*
			 * This partition is entirely after the other
			 * partition.
			 */
			continue;
		}

		efi_checkf_add(dkc, i, true, "[%llu, %llu] overlaps with "
		    "partition %d [%llu, %llu]",
		    part->p_start, part_end(part),
		    other, other_start, other_end);
	}
}

/*
 * Perform a series of consistency checks so that we can reject invalid labels;
 * e.g., those with overlapping partitions.
 */
static dk_check_t *
check_input(struct dk_gpt *vtoc)
{
	/*
	 * Allocate the check object we will use to track issues with the
	 * provided label:
	 */
	dk_check_t *dkc;
	if ((dkc = efi_check_alloc()) == NULL) {
		return (NULL);
	}

	for (uint_t i = 0; i < vtoc->efi_nparts; i++) {
		check_input_one(vtoc, &vtoc->efi_parts[i], i, dkc);
	}

	if (dkc->dkc_resv_part == -1) {
		efi_checkf_add(dkc, MISC, false, "no reserved partition found");
	}

	return (dkc);
}

/*
 * Set *lastp_p to the last non-reserved partition with the last (highest)
 * LBA (and set *last_lbap to the last used LBA). We also will fail if the
 * partition layout isn't as expected (reserved partiton last, no overlap
 * with the last partiton).
 */
static int
efi_use_whole_disk_get_last(struct dk_gpt *l, struct dk_part **lastp_p,
    diskaddr_t *last_lbap)
{
	struct dk_part *last_p = NULL;
	struct dk_part *resv_p = NULL;
	diskaddr_t last_ulba = 0;
	uint_t i;

	if (l->efi_nparts < 2) {
		efi_debugf("%s: too few (%u) partitions", __func__,
		    l->efi_nparts);
		return (-1);
	}

	/*
	 * Look for the last (highest) used LBA. We ignore the last
	 * (efi_nparts - 1) partition since that should be the reserved
	 * partition (which is checked later).
	 */
	for (i = 0; i < l->efi_nparts - 1; i++) {
		struct dk_part *p = &l->efi_parts[i];
		diskaddr_t end;

		if (p->p_tag == V_RESERVED) {
			efi_debugf("%s: reserved partition found at "
			    "unexpected position (%u)", __func__, i);
			return (-1);
		}

		/* Ignore empty partitions */
		if (p->p_size == 0)
			continue;

		end = part_end(p);
		if (last_ulba < end) {
			last_p = p;
			last_ulba = end;
		}
	}

	if (l->efi_parts[l->efi_nparts - 1].p_tag != V_RESERVED) {
		efi_debugf("%s: no reserved partition", __func__);
		return (-1);
	}

	resv_p = &l->efi_parts[l->efi_nparts - 1];

	/*
	 * The reserved partition should start after the last (highest)
	 * LBA used by any other partition.
	 */
	if (resv_p->p_start <= last_ulba) {
		efi_debugf("%s: reserved partition not after other partitions", 
		    __func__);
		return (-1);
	}

	*lastp_p = last_p;
	*last_lbap = last_ulba;
	return (0);
}

/*
 * Add all the unallocated space to the current label.
 */
int
efi_use_whole_disk(int fd)
{
	struct dk_gpt		*efi_label;
	struct dk_part		*resv_p = NULL;
	struct dk_part		*last_p = NULL;
	diskaddr_t		last_lba = 0;
	int			rval;
	uint_t			nblocks;
	boolean_t		save = B_FALSE;

	rval = efi_alloc_and_read(fd, &efi_label);
	if (rval < 0) {
		return (rval);
	}

	rval = efi_use_whole_disk_get_last(efi_label, &last_p, &last_lba);
	if (rval < 0) {
		efi_free(efi_label);
		return (VT_EINVAL);
	}
	resv_p = &efi_label->efi_parts[efi_label->efi_nparts - 1];
	ASSERT3U(resv_p->p_tag, ==, V_RESERVED);

	/*
	 * If we aren't using the backup label (efi_altern_lba == 1)
	 * and the backup label isn't at the end of the disk, move the backup
	 * label to the end of the disk. efi_read() sets efi_last_lba based
	 * on the capacity of the disk, so we don't need to re-read the
	 * capacity again to get the last LBA.
	 */
	if (efi_label->efi_altern_lba != 1 &&
	    efi_label->efi_altern_lba != efi_label->efi_last_lba) {
		efi_label->efi_altern_lba = efi_label->efi_last_lba;
		save = B_TRUE;
	}

	/*
	 * This is similar to the logic used in efi_alloc_and_init(). Based
	 * on the number of partitions (and the minimum number of entries
	 * required for an EFI label), determine the size of the backup label.
	 */
	nblocks = NBLOCKS(efi_label->efi_nparts, efi_label->efi_lbasize);
	if ((nblocks * efi_label->efi_lbasize) < EFI_MIN_ARRAY_SIZE +
	    efi_label->efi_lbasize) {
		nblocks = EFI_MIN_ARRAY_SIZE / efi_label->efi_lbasize + 1;
	}

	/* efi_last_u_lba should be the last LBA before the backup label */
	if (efi_label->efi_last_u_lba < efi_label->efi_last_lba - nblocks) {
		efi_label->efi_last_u_lba = efi_label->efi_last_lba - nblocks;
		save = B_TRUE;
	}

	/*
	 * If there is unused space after the reserved partition, move it to
	 * the end of the disk. There is currently no data in here except
	 * fabricated devids (which are generated via efi_write()). Therefore,
	 * there is no need to copy the contents.
	 */
	if (resv_p->p_start + resv_p->p_size - 1 < efi_label->efi_last_u_lba) {
		diskaddr_t new_start =
		    efi_label->efi_last_u_lba - resv_p->p_size + 1;

		if (resv_p->p_start > new_start) {
			efi_debugf("%s: reserved partition size mismatch", 
			    __func__);
			efi_free(efi_label);
			return (VT_EINVAL);
		}

		resv_p->p_start = new_start;
		save = B_TRUE;
	}

	/*
	 * If there is space between the last (non-reserved) partition and
	 * the reserved partition, grow the last partition.
	 */
	if (last_lba < resv_p->p_start) {
		last_p->p_size += resv_p->p_start - last_lba - 1;
		save = B_TRUE;
	}

	if (!save) {
		efi_free(efi_label);
		return (0);
	}

	rval = efi_write(fd, efi_label);
	if (rval < 0) {
		efi_debugf("efi_use_whole_disk: fail to write label, rval=%d",
		    rval);
		efi_free(efi_label);
		return (rval);
	}

	efi_free(efi_label);
	return (0);
}


/*
 * Write an EFI label and backup label.  The caller will receive errors and
 * warnings through "dkcp", and is responsible for checking and freeing the
 * pointer.  Even if this routine succeeds, non-fatal warnings may be provided
 * via the check object.
 */
int
efi_write_with_errors(int fd, struct dk_gpt *vtoc, dk_check_t **dkcp)
{
	dk_efi_t dk_ioc;
	efi_gpt_t *efi;
	efi_gpe_t *efi_parts;
	int i, j;
	struct dk_cinfo dki_info;
	int nblocks;
	diskaddr_t lba_backup_gpt_hdr;

	*dkcp = NULL;

	if (ioctl(fd, DKIOCINFO, (caddr_t)&dki_info) == -1) {
		efi_debugf("DKIOCINFO errno 0x%x", errno);

		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		default:
			return (VT_ERROR);
		}
	}

	if ((*dkcp = check_input(vtoc)) == NULL) {
		return (VT_ERROR);
	}

	if (!efi_check_ok(*dkcp)) {
		return (VT_EINVAL);
	}

	dk_ioc.dki_lba = 1;
	if (NBLOCKS(vtoc->efi_nparts, vtoc->efi_lbasize) < 34) {
		dk_ioc.dki_length = EFI_MIN_ARRAY_SIZE + vtoc->efi_lbasize;
	} else {
		dk_ioc.dki_length = NBLOCKS(vtoc->efi_nparts,
		    vtoc->efi_lbasize) *
		    vtoc->efi_lbasize;
	}

	/*
	 * the number of blocks occupied by GUID partition entry array
	 */
	nblocks = dk_ioc.dki_length / vtoc->efi_lbasize - 1;

	/*
	 * Backup GPT header is located on the block after GUID
	 * partition entry array. Here, we calculate the address
	 * for backup GPT header.
	 */
	lba_backup_gpt_hdr = vtoc->efi_last_u_lba + 1 + nblocks;
	if ((dk_ioc.dki_data = calloc(1, dk_ioc.dki_length)) == NULL)
		return (VT_ERROR);

	efi = dk_ioc.dki_data;

	/* stuff user's input into EFI struct */
	efi->efi_gpt_Signature = LE_64(EFI_SIGNATURE);
	efi->efi_gpt_Revision = LE_32(vtoc->efi_version); /* 0x02000100 */
	efi->efi_gpt_HeaderSize = LE_32(EFI_HEADER_SIZE);
	efi->efi_gpt_Reserved1 = 0;
	efi->efi_gpt_MyLBA = LE_64(1ULL);
	efi->efi_gpt_AlternateLBA = LE_64(lba_backup_gpt_hdr);
	efi->efi_gpt_FirstUsableLBA = LE_64(vtoc->efi_first_u_lba);
	efi->efi_gpt_LastUsableLBA = LE_64(vtoc->efi_last_u_lba);
	efi->efi_gpt_PartitionEntryLBA = LE_64(2ULL);
	efi->efi_gpt_NumberOfPartitionEntries = LE_32(vtoc->efi_nparts);
	efi->efi_gpt_SizeOfPartitionEntry = LE_32(sizeof (struct efi_gpe));
	UUID_LE_CONVERT(efi->efi_gpt_DiskGUID, vtoc->efi_disk_uguid);

	efi_parts = (efi_gpe_t *)((char *)dk_ioc.dki_data + vtoc->efi_lbasize);

	for (i = 0; i < vtoc->efi_nparts; i++) {
		struct dk_part *p = &vtoc->efi_parts[i];

		for (j = 0; j < NCONVERSIONS; j++) {
			if (p->p_tag == conversions[j].p_tag) {
				UUID_LE_CONVERT(
				    efi_parts[i].efi_gpe_PartitionTypeGUID,
				    conversions[j].uuid);
				break;
			}
		}

		if (j == NCONVERSIONS) {
			/*
			 * If we didn't have a matching uuid match, bail here.
			 * Don't write a label with unknown uuid.
			 */
			efi_debugf("unknown uuid for p_tag %d\n", p->p_tag);
			return (VT_EINVAL);
		}

		efi_parts[i].efi_gpe_StartingLBA = LE_64(p->p_start);
		efi_parts[i].efi_gpe_EndingLBA = LE_64(part_end(p));
		efi_parts[i].efi_gpe_Attributes.PartitionAttrs =
		    LE_16(p->p_flag);
		for (j = 0; j < EFI_PART_NAME_LEN; j++) {
			efi_parts[i].efi_gpe_PartitionName[j] =
			    LE_16((ushort_t)p->p_name[j]);
		}
		if (p->p_tag != V_UNASSIGNED &&
		    uuid_is_null((uchar_t *)&p->p_uguid)) {
			(void) uuid_generate((uchar_t *)
			    &vtoc->efi_parts[i].p_uguid);
		}
		bcopy(&p->p_uguid, &efi_parts[i].efi_gpe_UniquePartitionGUID,
		    sizeof (uuid_t));
	}
	efi->efi_gpt_PartitionEntryArrayCRC32 =
	    LE_32(efi_crc32((unsigned char *)efi_parts,
	    vtoc->efi_nparts * (int)sizeof (struct efi_gpe)));
	efi->efi_gpt_HeaderCRC32 = LE_32(efi_crc32((unsigned char *)efi,
	    EFI_HEADER_SIZE));

	if (efi_ioctl(fd, DKIOCSETEFI, &dk_ioc) == -1) {
		free(dk_ioc.dki_data);
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		default:
			return (VT_ERROR);
		}
	}

	/* write backup partition array */
	dk_ioc.dki_lba = vtoc->efi_last_u_lba + 1;
	dk_ioc.dki_length -= vtoc->efi_lbasize;
	dk_ioc.dki_data = (efi_gpt_t *)((char *)dk_ioc.dki_data +
	    vtoc->efi_lbasize);

	if (efi_ioctl(fd, DKIOCSETEFI, &dk_ioc) == -1) {
		/*
		 * We wrote the primary label okay, so don't fail.
		 */
		efi_debugf("write of backup partitions to block %llu "
		    "failed, errno %d", vtoc->efi_last_u_lba + 1, errno);
	}

	/*
	 * now swap MyLBA and AlternateLBA fields and write backup
	 * partition table header
	 */
	dk_ioc.dki_lba = lba_backup_gpt_hdr;
	dk_ioc.dki_length = vtoc->efi_lbasize;
	dk_ioc.dki_data = (efi_gpt_t *)((char *)dk_ioc.dki_data -
	    vtoc->efi_lbasize);
	efi->efi_gpt_AlternateLBA = LE_64(1ULL);
	efi->efi_gpt_MyLBA = LE_64(lba_backup_gpt_hdr);
	efi->efi_gpt_PartitionEntryLBA = LE_64(vtoc->efi_last_u_lba + 1);
	efi->efi_gpt_HeaderCRC32 = 0;
	efi->efi_gpt_HeaderCRC32 =
	    LE_32(efi_crc32((unsigned char *)dk_ioc.dki_data, EFI_HEADER_SIZE));

	if (efi_ioctl(fd, DKIOCSETEFI, &dk_ioc) == -1) {
		efi_debugf("write of backup header to block %llu failed, "
		    "errno %d", lba_backup_gpt_hdr, errno);
	}

	(void) write_pmbr(fd, vtoc);

	free(dk_ioc.dki_data);
	return (0);
}

/*
 * Write an EFI label and backup label.  This is the original Committed
 * entrypoint which does not offer any specifics on label validation errors.
 */
int
efi_write(int fd, struct dk_gpt *vtoc)
{
	dk_check_t *dkcp = NULL;

	int r = efi_write_with_errors(fd, vtoc, &dkcp);

	efi_check_free(dkcp);

	return (r);
}

void
efi_free(struct dk_gpt *ptr)
{
	free(ptr);
}

/*
 * Input: File descriptor
 * Output: 1 if disk has an EFI label, or > 2TB with no VTOC or legacy MBR.
 * Otherwise 0.
 */
int
efi_type(int fd)
{
	struct vtoc vtoc;
	struct extvtoc extvtoc;

	if (ioctl(fd, DKIOCGEXTVTOC, &extvtoc) == -1) {
		switch (errno) {
		case ENOTSUP:
			return (1);
		case ENOTTY:
			if (ioctl(fd, DKIOCGVTOC, &vtoc) == -1) {
				if (errno == ENOTSUP)
					return (1);
			}
			break;
		}
	}

	return (0);
}

/*
 * Construct a default EFI partition table for a blank disk, with partitions
 * sized automatically to fill the disk.  The default partition layout here is
 * largely historical, and only used by rmformat(1) for automatically
 * formatting removable media.
 */
int
efi_auto_sense(int fd, struct dk_gpt **vtocp)
{
	struct dk_gpt *vtoc;

	if (efi_alloc_and_init(fd, EFI_NUMPAR, &vtoc) != 0) {
		efi_debugf("efi_alloc_and_init() failed");
		*vtocp = NULL;
		return (-1);
	}

	for (uint_t i = 0; i < min(vtoc->efi_nparts, V_NUMPAR); i++) {
		partn(vtoc, i)->p_tag = default_vtoc_map_rmformat[i].p_tag;
		partn(vtoc, i)->p_flag = default_vtoc_map_rmformat[i].p_flag;
		partn(vtoc, i)->p_start = 0;
		partn(vtoc, i)->p_size = 0;
	}

	/*
	 * Create partition 0 for the root file system at the first available
	 * offset, and make it 128 MB:
	 */
	partn(vtoc, 0)->p_start = EFI_MIN_ARRAY_SIZE / vtoc->efi_lbasize + 2;
	partn(vtoc, 0)->p_size = (128 * 1024 * 1024) / vtoc->efi_lbasize;

	/*
	 * Place partition 1 directly after partition 0, and make it the same
	 * size:
	 */
	partn(vtoc, 1)->p_start = part_end(partn(vtoc, 0)) + 1;
	partn(vtoc, 1)->p_size = partn(vtoc, 0)->p_size;

	/*
	 * Partition 6 for /usr is next, and should use the bulk of the
	 * available space:
	 */
	/* partition - s6 /usr partition - HOG */
	partn(vtoc, 6)->p_start = part_end(partn(vtoc, 1)) + 1;
	partn(vtoc, 6)->p_size = vtoc->efi_last_u_lba + 1 -
	    partn(vtoc, 6)->p_start - efi_reserved_sectors(vtoc);

	/*
	 * Partition 8 is the EFI reserved partition, at the end of the useable
	 * space:
	 */
	partn(vtoc, 8)->p_start = part_end(partn(vtoc, 6)) + 1;
	partn(vtoc, 8)->p_size = efi_reserved_sectors(vtoc);
	partn(vtoc, 8)->p_tag = V_RESERVED;

	*vtocp = vtoc;
	return (0);
}
