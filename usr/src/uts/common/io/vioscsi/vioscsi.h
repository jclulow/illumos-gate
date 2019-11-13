/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joshua M. Clulow <josh@sysmgr.org>
 */

#ifndef	_VIOSCSI_H
#define	_VIOSCSI_H

#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/containerof.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/spc3_types.h>
#include <sys/avl.h>
#include <sys/policy.h>
#include "virtio.h"

#define	VIOSCSI_IPORT				"v0"

/*
 * The maintenance routine ... XXX.  The time is expressed in seconds.
 */
#define	VIOSCSI_PERIODIC_RATE			5

/*
 * VIRTIO SCSI FEATURE BITS
 */

#define	VIRTIO_SCSI_F_INOUT			(1ULL << 0)
/*
 * A single request can include both device-readable and device-writable data
 * buffers.
 */

#define	VIRTIO_SCSI_F_HOTPLUG			(1ULL << 1)
/*
 * The host SHOULD enable reporting of hot-plug and hot-unplug events for LUNs
 * and targets on the SCSI bus. The guest SHOULD handle hot-plug and hot-unplug
 * events.
 */

#define	VIRTIO_SCSI_F_CHANGE			(1ULL << 2)
/*
 * The host will report changes to LUN parameters via a
 * VIRTIO_SCSI_T_PARAM_CHANGE event; the guest SHOULD handle them.
 */

#define	VIRTIO_SCSI_F_T10_PI			(1ULL << 3)
/*
 * The extended fields for T10 protection information (DIF/DIX) are included in
 * the SCSI request header.
 */

/*
 * VIRTIO SCSI CONFIGURATION REGISTERS
 */
#define	VIRTIO_SCSI_CFG_NUM_QUEUES		0x00	/* 32 */
#define	VIRTIO_SCSI_CFG_SEG_MAX			0x04	/* 32 */
#define	VIRTIO_SCSI_CFG_MAX_SECTORS		0x08	/* 32 */
#define	VIRTIO_SCSI_CFG_CMD_PER_LUN		0x0c	/* 32 */
#define	VIRTIO_SCSI_CFG_EVENT_INFO_SIZE		0x10	/* 32 */
#define	VIRTIO_SCSI_CFG_SENSE_SIZE		0x14	/* 32 */
#define	VIRTIO_SCSI_CFG_CDB_SIZE		0x18	/* 32 */
#define	VIRTIO_SCSI_CFG_MAX_CHANNEL		0x1c	/* 16 */
#define	VIRTIO_SCSI_CFG_MAX_TARGET		0x1e	/* 16 */
#define	VIRTIO_SCSI_CFG_MAX_LUN			0x20	/* 32 */

/*
 * VIRTIO SCSI VIRTQUEUES
 */
#define	VIRTIO_SCSI_VIRTQ_CONTROL		0
#define	VIRTIO_SCSI_VIRTQ_EVENT			1
#define	VIRTIO_SCSI_VIRTQ_REQUEST		2

/*
 * VIRTIO SCSI ... XXX
 */
#define	VIRTIO_SCSI_S_OK			0
#define	VIRTIO_SCSI_S_OVERRUN			1
#define	VIRTIO_SCSI_S_ABORTED			2
#define	VIRTIO_SCSI_S_BAD_TARGET		3
#define	VIRTIO_SCSI_S_RESET			4
#define	VIRTIO_SCSI_S_BUSY			5
#define	VIRTIO_SCSI_S_TRANSPORT_FAILURE		6
#define	VIRTIO_SCSI_S_TARGET_FAILURE		7
#define	VIRTIO_SCSI_S_NEXUS_FAILURE		8
#define	VIRTIO_SCSI_S_FAILURE			9
#define	VIRTIO_SCSI_S_FUNCTION_SUCCEEDED	10
#define	VIRTIO_SCSI_S_FUNCTION_REJECTED		11
#define	VIRTIO_SCSI_S_INCORRECT_LUN		12

/*
 * VIRTIO SCSI CONTROL COMMAND TYPES? XXX
 */
#define	VIRTIO_SCSI_T_TMF			0

#define	VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET	4
#define	VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET	5

/*
 * VIRTIO SCSI EVENT TYPES
 */
#define	VIRTIO_SCSI_T_NO_EVENT			0

#define	VIRTIO_SCSI_T_TRANSPORT_RESET		1
#define	VIRTIO_SCSI_EVT_RESET_HARD		0
#define	VIRTIO_SCSI_EVT_RESET_RESCAN		1
#define	VIRTIO_SCSI_EVT_RESET_REMOVED		2

#define	VIRTIO_SCSI_T_ASYNC_NOTIFY		2

#define	VIRTIO_SCSI_T_PARAM_CHANGE		3


typedef enum vioscsi_init_level {
	VIOSCSI_INITLEVEL_BASIC =		(0x1 << 0),
	VIOSCSI_INITLEVEL_VIRTIO =		(0x1 << 1),
	VIOSCSI_INITLEVEL_MUTEX =		(0x1 << 2),
	VIOSCSI_INITLEVEL_TASKQ =		(0x1 << 3),
	VIOSCSI_INITLEVEL_PERIODIC =		(0x1 << 4),
	VIOSCSI_INITLEVEL_SCSA =		(0x1 << 6),
} vioscsi_init_level_t;

#define	INITLEVEL_SET(_vis, name)					\
	do {								\
		VERIFY(!((_vis)->vis_init_level & (name)));		\
		(_vis)->vis_init_level |= (name);			\
	} while (0)
#define	INITLEVEL_CLEAR(_vis, name)					\
	do { 								\
		VERIFY((_vis)->vis_init_level & (name));		\
		(_vis)->vis_init_level &= ~(name);			\
	} while (0)
#define	INITLEVEL_ACTIVE(_vis, name)					\
	(((_vis)->vis_init_level & (name)) != 0)

typedef struct vioscsi_target vioscsi_target_t;
typedef struct vioscsi_cmd vioscsi_cmd_t;
typedef struct vioscsi_cmd_scsa vioscsi_cmd_scsa_t;
typedef struct vioscsi vioscsi_t;

typedef enum {
	VIOSCSI_CMDQ_CONTROL = 1000,
	VIOSCSI_CMDQ_EVENT,
	VIOSCSI_CMDQ_REQUEST
} vioscsi_queue_name_t;

typedef enum vioscsi_status {
	VIOSCSI_STATUS_DETACHING =		(0x1 << 0),

	VIOSCSI_STATUS_DISCOVERY_RUNNING =	(0x1 << 1),
	VIOSCSI_STATUS_DISCOVERY_REQUESTED =	(0x1 << 2),
	VIOSCSI_STATUS_DISCOVERY_PERIODIC =	(0x1 << 3),
} vioscsi_status_t;

#define	VIOSCSI_STATUS_DISCOVERY_MASK					\
	(VIOSCSI_STATUS_DISCOVERY_RUNNING |				\
	VIOSCSI_STATUS_DISCOVERY_REQUESTED |				\
	VIOSCSI_STATUS_DISCOVERY_PERIODIC)

struct vioscsi {
	dev_info_t		*vis_dip;
	uint32_t		vis_instance;

	kmutex_t		vis_mutex;
	kcondvar_t		vis_cv_finish;
	vioscsi_status_t	vis_status;
	vioscsi_init_level_t	vis_init_level;

	scsi_hba_tran_t		*vis_hba_tran;
	dev_info_t		*vis_iport;
	scsi_hba_tgtmap_t	*vis_tgtmap;
	ddi_dma_attr_t		vis_hba_dma_attr;

	uint64_t		vis_next_tag;

	virtio_t		*vis_virtio;

	virtio_queue_t		*vis_q_control;
	virtio_queue_t		*vis_q_event;
	virtio_queue_t		*vis_q_request;

	uint32_t		vis_seg_max;
	uint32_t		vis_cdb_size;
	uint32_t		vis_sense_size;
	uint32_t		vis_event_info_size;
	uint32_t		vis_max_channel;
	uint32_t		vis_max_target_raw;
	uint32_t		vis_max_target;
	uint32_t		vis_max_lun_raw;
	uint32_t		vis_max_lun;
	uint32_t		vis_max_sectors;

	ddi_taskq_t		*vis_discover_taskq;
	hrtime_t		vis_time_last_discovery;

	ddi_periodic_t		vis_periodic;
};

/*
 * SCSA target tracking structure.
 */
struct vioscsi_target {
	vioscsi_t		*vist_vioscsi;
	struct scsi_device	*vist_scsi_dev;
	uint8_t			vist_lun[8];
};

#pragma pack(1)
struct virtio_scsi_ctrl_tmf_read {
	uint32_t vstmf_type;
	uint32_t vstmf_subtype;
	uint8_t vstmf_lun[8];
	uint64_t vstmf_id;
};
struct virtio_scsi_ctrl_tmf_write {
	uint8_t vstmf_response;
};
struct virtio_scsi_ctrl_tmf {
	struct virtio_scsi_ctrl_tmf_read vstmf_read;
	struct virtio_scsi_ctrl_tmf_write vstmf_write;
};

struct virtio_scsi_event {
	/*
	 * Entirely device-writeable.
	 */
	uint32_t vsev_event;
	uint8_t vsev_lun[8];
	uint32_t vsev_reason;
};

struct virtio_scsi_req_cmd_read {
	uint8_t vsrq_lun[8];
	uint64_t vsrq_id;
	uint8_t vsrq_task_attr;
	uint8_t vsrq_prio;
	uint8_t vsrq_crn;
	uint8_t vsrq_cdb[];
};
/*
 *	char vsrq_dataout[];
 */
struct virtio_scsi_req_cmd_write {
	uint32_t vsrq_sense_len;
	uint32_t vsrq_residual;
	uint16_t vsrq_status_qualifier;
	uint8_t vsrq_status;
	uint8_t vsrq_response;
	uint8_t vsrq_sense[];
};
/*
 * 	char vsrq_datain[];
 */
#pragma pack()

/*
 * Ensure that the compiler is not adding any padding, or treating the flexible
 * array member as anything but empty.  If this is not true, the
 * device-writeable half of the request structure may be at the wrong offset.
 */
CTASSERT(offsetof(struct virtio_scsi_req_cmd_write, vsrq_sense) ==
    sizeof (struct virtio_scsi_req_cmd_write));
CTASSERT(offsetof(struct virtio_scsi_req_cmd_read, vsrq_cdb) ==
    sizeof (struct virtio_scsi_req_cmd_read));

struct vioscsi_cmd_scsa {
	struct scsi_pkt *vscs_pkt;
	vioscsi_cmd_t *vscs_cmd;
};

typedef enum vioscsi_cmd_type {
	/*
	 * Request queue events:
	 */
	VIOSCSI_CMDTYPE_INTERNAL =		0x4000,
	VIOSCSI_CMDTYPE_SCSA,

	/*
	 * Events for other queues:
	 */
	VIOSCSI_CMDTYPE_EVENT,
	VIOSCSI_CMDTYPE_CONTROL,
} vioscsi_cmd_type_t;

typedef enum vioscsi_cmd_status {
	VIOSCSI_CMD_STATUS_INFLIGHT =		(0x1 << 0),
	VIOSCSI_CMD_STATUS_COMPLETE =		(0x1 << 1),
	VIOSCSI_CMD_STATUS_POLLED =		(0x1 << 2),
	VIOSCSI_CMD_STATUS_POLL_COMPLETE =	(0x1 << 3),
	VIOSCSI_CMD_STATUS_TRAN_START =		(0x1 << 4),
	VIOSCSI_CMD_STATUS_ERROR =		(0x1 << 5),
} vioscsi_cmd_status_t;

struct vioscsi_cmd {
	vioscsi_cmd_type_t vsc_type;
	vioscsi_t *vsc_vioscsi;
	virtio_queue_t *vsc_q;

	vioscsi_cmd_status_t vsc_status;
	hrtime_t vsc_time_push;

	virtio_dma_t *vsc_dma;

	virtio_chain_t *vsc_chain;

	offset_t vsc_response_offset;
	vioscsi_cmd_scsa_t *vsc_scsa;
};

/*
 * COMMAND MANAGEMENT ROUTINES
 */
extern vioscsi_cmd_t *vioscsi_cmd_alloc(vioscsi_t *, virtio_queue_t *, size_t);
extern void vioscsi_cmd_free(vioscsi_cmd_t *);

extern void vioscsi_cmd_clear(vioscsi_cmd_t *);
extern struct vq_entry *vioscsi_cmd_append(vioscsi_cmd_t *);

extern int vioscsi_cmd_comparator(const void *, const void *);

/*
 * VIRTQUEUE WRAPPER
 */
extern void vioscsi_q_push(vioscsi_cmd_t *);
extern vioscsi_cmd_t *vioscsi_q_pull(vioscsi_t *, virtio_queue_t *);

/*
 * SHARED DATA
 */
extern ddi_dma_attr_t vioscsi_dma_attr;
extern ddi_device_acc_attr_t virtio_attr; /* XXX move to virtio code... */

#endif	/* !_VIOSCSI_H */
