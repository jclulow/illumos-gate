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

#include "vioscsi.h"

void *vioscsi_state;
int vioscsi_force_discovery = 0;

static int vioscsi_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioscsi_detach(dev_info_t *, ddi_detach_cmd_t);
static int vioscsi_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static void vioscsi_cleanup(vioscsi_t *, boolean_t);
static void vioscsi_hba_complete(vioscsi_cmd_t *);
static void vioscsi_discover_request(vioscsi_t *);

static struct cb_ops vioscsi_cb_ops = {
	.cb_rev =		CB_REV,
	.cb_flag =		D_NEW | D_MP,

	.cb_open =		scsi_hba_open,
	.cb_close =		scsi_hba_close,

	.cb_ioctl =		vioscsi_ioctl,

	.cb_strategy =		nodev,
	.cb_print =		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_devmap =		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_str =		NULL,
	.cb_aread =		nodev,
	.cb_awrite =		nodev
};

/*
 * Device Operations Structure
 */
static struct dev_ops vioscsi_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,

	.devo_attach =		vioscsi_attach,
	.devo_detach =		vioscsi_detach,

	.devo_cb_ops =		&vioscsi_cb_ops,

	.devo_getinfo =		ddi_no_info,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_reset =		nodev,
	.devo_bus_ops =		NULL,
	.devo_power =		nodev,
	.devo_quiesce =		nodev
};

/*
 * Linkage structures
 */
static struct modldrv vioscsi_modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"VIRTIO SCSI driver",
	.drv_dev_ops =		&vioscsi_dev_ops
};

static struct modlinkage vioscsi_modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ &vioscsi_modldrv, NULL }
};

/*
 * XXX
 */
ddi_dma_attr_t vioscsi_dma_attr = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x00000000,
	.dma_attr_addr_hi =		0xFFFFFFFF,
	.dma_attr_count_max =		0xFFFFFFFF,
	.dma_attr_align =		1,
	.dma_attr_burstsizes =		1,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0xFFFFFFFF,
	.dma_attr_seg =			0xFFFFFFFF,
	.dma_attr_sgllen =		1,
	.dma_attr_granular =		1, /* XXX? */
	.dma_attr_flags =		0
};

int
_init()
{
	int r;

	VERIFY0(ddi_soft_state_init(&vioscsi_state, sizeof (vioscsi_t), 0));

	if ((r = scsi_hba_init(&vioscsi_modlinkage)) != 0) {
		goto fail;
	}

	if ((r = mod_install(&vioscsi_modlinkage)) != 0) {
		scsi_hba_fini(&vioscsi_modlinkage);
		goto fail;
	}

	return (r);

fail:
	ddi_soft_state_fini(&vioscsi_state);
	return (r);
}

int
_fini()
{
	int r;

	if ((r = mod_remove(&vioscsi_modlinkage)) == 0) {
		scsi_hba_fini(&vioscsi_modlinkage);
		ddi_soft_state_fini(&vioscsi_state);
	}

	return (r);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vioscsi_modlinkage, modinfop));
}

static int
vioscsi_fill_events(vioscsi_t *vis)
{
	size_t sz = MAX(sizeof (struct virtio_scsi_event),
	    vis->vis_event_info_size);

	/*
	 * Put 64 buffers in the event queue, just in case.
	 */
	for (uint_t n = 0; n < 64; n++) {
		vioscsi_cmd_t *vsc;
		struct vq_entry *ve;

		if ((vsc = vioscsi_cmd_alloc(vis, vis->vis_q_event, sz)) ==
		    NULL) {
			break;
		}
		vsc->vsc_type = VIOSCSI_CMDTYPE_EVENT;

		if (virtio_chain_append(vsc->vsc_chain,
		    virtio_dma_cookie_pa(vsc->vsc_dma, 0),
		    virtio_dma_cookie_size(vsc->vsc_dma, 0),
		    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
			vioscsi_cmd_free(vsc);
			break;
		}

		mutex_enter(&vis->vis_mutex);
		vioscsi_q_push(vsc);
		mutex_exit(&vis->vis_mutex);
	}

	return (DDI_SUCCESS);
}

static vioscsi_cmd_t *
vioscsi_report_luns_alloc(vioscsi_t *vis, uint_t target)
{
	vioscsi_cmd_t *vsc;

	struct virtio_scsi_req_cmd_read *vsrq;
	size_t req_sz = sizeof (*vsrq) + vis->vis_cdb_size;
	size_t datain_sz = 2048;
	size_t res_sz = sizeof (struct virtio_scsi_req_cmd_write) +
	    vis->vis_sense_size + datain_sz;

	/*
	 * Allocate an object into which we will write the command header and
	 * the CDB.
	 */
	if ((vsc = vioscsi_cmd_alloc(vis, vis->vis_q_request,
	    req_sz + res_sz)) == NULL) {
		dev_err(vis->vis_dip, CE_WARN, "could not allocate command "
		    "for REPORT LUNS (%u)", target);
		return (NULL);
	}
	vsrq = virtio_dma_va(vsc->vsc_dma, 0);

	/*
	 * XXX Mark this command as an internal command for which we will poll
	 * for the result.
	 */
	vsc->vsc_type = VIOSCSI_CMDTYPE_INTERNAL;
	vsc->vsc_status |= VIOSCSI_CMD_STATUS_POLLED;

	vsrq->vsrq_lun[0] = 0x01; /* fixed at 0x01 */
	vsrq->vsrq_lun[1] = target; /* target */
	vsrq->vsrq_lun[2] = 0x00; /* LUN... */
	vsrq->vsrq_lun[3] = 0x00; /* LUN... */

	vsrq->vsrq_id = vis->vis_next_tag++; /* command tag */

	/*
	 * XXX Maybe use "spc3_report_luns_cdb_t" here?
	 */
	vsrq->vsrq_cdb[0] = SCMD_REPORT_LUNS;
	vsrq->vsrq_cdb[2] = SPC3_RL_SR_ALL; /* XXX SPC3_RL_SR_ADDRESSING; ? */
	vsrq->vsrq_cdb[6] = (datain_sz >> (3 * 8)) & 0xFF; /* MSB */
	vsrq->vsrq_cdb[7] = (datain_sz >> (2 * 8)) & 0xFF;
	vsrq->vsrq_cdb[8] = (datain_sz >> (1 * 8)) & 0xFF;
	vsrq->vsrq_cdb[9] = (datain_sz >> (0 * 8)) & 0xFF; /* LSB */
	vsrq->vsrq_cdb[11] = 0; /* XXX CONTROL byte? */

	bcopy(vsrq, virtio_dma_va(vsc->vsc_dma, 0), req_sz);

	/*
	 * Store the offset at which the response begins within the DMA memory.
	 */
	vsc->vsc_response_offset = req_sz;

	if (virtio_chain_append(vsc->vsc_chain,
	    virtio_dma_cookie_pa(vsc->vsc_dma, 0), req_sz,
	    VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS ||
	    virtio_chain_append(vsc->vsc_chain,
	    virtio_dma_cookie_pa(vsc->vsc_dma, 0) + vsc->vsc_response_offset,
	    res_sz, VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
		dev_err(vis->vis_dip, CE_WARN, "could not allocate descriptors "
		    "for REPORT LUNS (%u)", target);
		return (NULL);
	}

	return (vsc);
}

static uint_t
vioscsi_handle_control(caddr_t arg0, caddr_t arg1)
{
	vioscsi_t *vis = (vioscsi_t *)arg0;

#if 0
	dev_err(vis->vis_dip, CE_WARN, "vioscsi_handle_control");
#endif

	mutex_enter(&vis->vis_mutex);

	vioscsi_cmd_t *vsc;
	while ((vsc = vioscsi_q_pull(vis, vis->vis_q_control)) != NULL) {
		struct virtio_scsi_ctrl_tmf *vstmf =
		    virtio_dma_va(vsc->vsc_dma, 0);

		dev_err(vis->vis_dip, CE_WARN, "response: %u",
		    (uint_t)vstmf->vstmf_write.vstmf_response);

		vioscsi_cmd_free(vsc);
	}

	mutex_exit(&vis->vis_mutex);

	return (DDI_INTR_CLAIMED);
}

static uint_t
vioscsi_handle_event(caddr_t arg0, caddr_t arg1)
{
	vioscsi_t *vis = (vioscsi_t *)arg0;

#if 0
	dev_err(vis->vis_dip, CE_WARN, "vioscsi_handle_event");
#endif

	mutex_enter(&vis->vis_mutex);

	vioscsi_cmd_t *vsc;
	while ((vsc = vioscsi_q_pull(vis, vis->vis_q_event)) != NULL) {
		struct virtio_scsi_event *vsev = virtio_dma_va(vsc->vsc_dma, 0);
		dev_err(vis->vis_dip, CE_WARN,
		    "lun %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, "
		    "event: %x, reason: %x",
		    (uint_t)vsev->vsev_lun[0],
		    (uint_t)vsev->vsev_lun[1],
		    (uint_t)vsev->vsev_lun[2],
		    (uint_t)vsev->vsev_lun[3],
		    (uint_t)vsev->vsev_lun[4],
		    (uint_t)vsev->vsev_lun[5],
		    (uint_t)vsev->vsev_lun[6],
		    (uint_t)vsev->vsev_lun[7],
		    vsev->vsev_event, vsev->vsev_reason);

		if (vsev->vsev_event == VIRTIO_SCSI_T_TRANSPORT_RESET) {
			uint32_t r = vsev->vsev_reason;

			if (r == VIRTIO_SCSI_EVT_RESET_RESCAN ||
			    r == VIRTIO_SCSI_EVT_RESET_REMOVED) {
				dev_err(vis->vis_dip, CE_WARN,
				    "rescan discovery requested");
				vioscsi_discover_request(vis);
			}
		}

		/*
		 * We want to keep a standing pool of event buffers, so put
		 * this one back in the ring.
		 */
		bzero(virtio_dma_va(vsc->vsc_dma, 0),
		    virtio_dma_size(vsc->vsc_dma));
		vioscsi_q_push(vsc);
	}

	mutex_exit(&vis->vis_mutex);

	return (DDI_INTR_CLAIMED);
}

static void
vioscsi_process_finishq_one(vioscsi_cmd_t *vsc)
{
	vioscsi_t *vis = vsc->vsc_vioscsi;

	VERIFY(MUTEX_HELD(&vis->vis_mutex));

	VERIFY(!(vsc->vsc_status & VIOSCSI_CMD_STATUS_COMPLETE));
	vsc->vsc_status |= VIOSCSI_CMD_STATUS_COMPLETE;

	switch (vsc->vsc_type) {
	case VIOSCSI_CMDTYPE_INTERNAL:
		cv_broadcast(&vis->vis_cv_finish);
		return;

	case VIOSCSI_CMDTYPE_SCSA:
		vioscsi_hba_complete(vsc);
		return;

	case VIOSCSI_CMDTYPE_EVENT:
	case VIOSCSI_CMDTYPE_CONTROL:
		panic("unexpected command type 0x%x in request queue",
		    vsc->vsc_type);
		return;
	}

	panic("unknown command type 0x%x", vsc->vsc_type);
}

static uint_t
vioscsi_handle_request(caddr_t arg0, caddr_t arg1)
{
	vioscsi_t *vis = (vioscsi_t *)arg0;

#if 0
	dev_err(vis->vis_dip, CE_WARN, "vioscsi_handle_request");
#endif

	mutex_enter(&vis->vis_mutex);

	vioscsi_cmd_t *vsc;
	while ((vsc = vioscsi_q_pull(vis, vis->vis_q_request)) != NULL) {
#if 0
		struct virtio_scsi_req_cmd_write *vsrq = vsc->vsc_va +
		    vsc->vsc_response_offset;

		dev_err(vis->vis_dip, CE_WARN, "scsi response (status %u "
		    "response %u residual %u)",
		    vsrq->vsrq_status,
		    vsrq->vsrq_response,
		    vsrq->vsrq_residual);
#endif

		/*
		 * XXX Determine how much to molest the SCSI packet before
		 * handing things back...
		 */

		if (vsc->vsc_status & VIOSCSI_CMD_STATUS_POLLED) {
			/*
			 * This command will be picked up and processed by
			 * "vioscsi_poll_for()" once the CV is triggered at the
			 * end of processing.
			 */
			vsc->vsc_status |= VIOSCSI_CMD_STATUS_POLL_COMPLETE;
			continue;
		}

		/*
		 * XXX Do we need a finishq, or is it OK to just process these
		 * in the interrupt handler?
		 */
		vioscsi_process_finishq_one(vsc);
	}

	cv_broadcast(&vis->vis_cv_finish);
	mutex_exit(&vis->vis_mutex);

	return (DDI_INTR_CLAIMED);
}

static void
vioscsi_hba_complete_log_error(vioscsi_cmd_t *vsc, const char *qual,
    const char *name)
{
	vioscsi_t *vis = vsc->vsc_vioscsi;
	struct scsi_pkt *pkt = vsc->vsc_scsa->vscs_pkt;
	struct scsi_device *sd;
	vioscsi_target_t *vist;
	struct virtio_scsi_req_cmd_read *vsrq = virtio_dma_va(vsc->vsc_dma, 0);
	struct virtio_scsi_req_cmd_write *vsrqw = virtio_dma_va(vsc->vsc_dma,
	    vsc->vsc_response_offset);

	VERIFY((sd = scsi_address_device(&pkt->pkt_address)) != NULL);
	VERIFY((vist = scsi_device_hba_private_get(sd)) != NULL);

	/*
	 * XXX use ! for log only
	 */
	dev_err(vis->vis_dip, CE_WARN, "SCSI command %s: %s: "
	    "lun %02x:%02x:%02x:%02x-%02x:%02x:%02x:%02x "
	    "SCSI op 0x%x, response %u, status 0x%x, status qual 0x%x, "
	    "sense len %u",
	    qual == NULL ? "failed" : qual,
	    name,
	    (uint_t)vist->vist_lun[0],
	    (uint_t)vist->vist_lun[1],
	    (uint_t)vist->vist_lun[2],
	    (uint_t)vist->vist_lun[3],
	    (uint_t)vist->vist_lun[4],
	    (uint_t)vist->vist_lun[5],
	    (uint_t)vist->vist_lun[6],
	    (uint_t)vist->vist_lun[7],
	    (uint_t)vsrq->vsrq_cdb[0],
	    (uint_t)vsrqw->vsrq_response,
	    (uint_t)vsrqw->vsrq_status,
	    (uint_t)vsrqw->vsrq_status_qualifier,
	    (uint_t)vsrqw->vsrq_sense_len);
}


/*
 * Completion routine for commands submitted to the controller via the SCSI
 * framework.
 */
static void
vioscsi_hba_complete(vioscsi_cmd_t *vsc)
{
	vioscsi_t *vis = vsc->vsc_vioscsi;
	struct scsi_pkt *pkt = vsc->vsc_scsa->vscs_pkt;
	struct virtio_scsi_req_cmd_write *vsrq = virtio_dma_va(vsc->vsc_dma,
	    vsc->vsc_response_offset);

	VERIFY(MUTEX_HELD(&vis->vis_mutex));

	DTRACE_PROBE1(vioscsi__hba__complete,
	    struct virtio_scsi_req_cmd_write *, vsrq);

	pkt->pkt_resid = vsrq->vsrq_residual;

	switch (vsrq->vsrq_response) {
	case VIRTIO_SCSI_S_OK:
		/*
		 * It would seem that everything went OK!
		 */
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;
		break;

	case VIRTIO_SCSI_S_OVERRUN:
		vioscsi_hba_complete_log_error(vsc, NULL, "data overrun");
		pkt->pkt_reason = CMD_DATA_OVR;
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;
		break;

	case VIRTIO_SCSI_S_ABORTED:
		vioscsi_hba_complete_log_error(vsc, NULL, "aborted");
		pkt->pkt_reason = CMD_ABORTED;
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;
		pkt->pkt_statistics |= STAT_ABORTED;
		break;

	case VIRTIO_SCSI_S_BAD_TARGET:
		vioscsi_hba_complete_log_error(vsc, NULL, "bad target");
		pkt->pkt_reason = CMD_INCOMPLETE;
		break;

	case VIRTIO_SCSI_S_RESET:
		vioscsi_hba_complete_log_error(vsc, NULL, "reset");
		pkt->pkt_reason = CMD_INCOMPLETE;
		break;

	case VIRTIO_SCSI_S_BUSY:
		vioscsi_hba_complete_log_error(vsc, NULL, "busy");
		pkt->pkt_reason = CMD_INCOMPLETE;
		break;

	case VIRTIO_SCSI_S_TRANSPORT_FAILURE:
		vioscsi_hba_complete_log_error(vsc, NULL, "transport failure");
		pkt->pkt_reason = CMD_TRAN_ERR;
		break;

	default:
		vioscsi_hba_complete_log_error(vsc, NULL, "unexpected failure");
		pkt->pkt_reason = CMD_TRAN_ERR;
		break;
	}

	boolean_t copy_sense_data = B_FALSE;
	if ((vsrq->vsrq_status & STATUS_MASK) == STATUS_CHECK) {
		if (vsrq->vsrq_sense_len == 0) {
			/*
			 * CHECK CONDITION without sense data seems unusual.
			 */
			vioscsi_hba_complete_log_error(vsc, "weird",
			    "CHECK CONDITION without sense data");
		} else if (pkt->pkt_scblen < sizeof (struct scsi_arq_status)) {
			/*
			 * We cannot write the sense data if the SCB is not
			 * large enough for the full ARQ object.
			 */
			vioscsi_hba_complete_log_error(vsc, "weird",
			    "CHECK CONDITION and sense data, but small SCB");
		} else {
			copy_sense_data = B_TRUE;
		}
	} else if (vsrq->vsrq_sense_len > 0) {
		/*
		 * It's not clear why we would receive sense data without a
		 * CHECK CONDITION.  Even less clear is what we should _do_
		 * with that sense data.
		 */
		vioscsi_hba_complete_log_error(vsc, "weird",
		    "have sense data but no CHECK CONDITION");
	}

	/*
	 * We must populate "pkt_scbp" according to scsi_pkt(9S).
	 */
	if (!copy_sense_data) {
		VERIFY3U(pkt->pkt_scblen, >=, 1);

		/*
		 * We do not intend to copy sense data, so just copy the SCSI
		 * status byte.
		 */
		bcopy(&vsrq->vsrq_status, pkt->pkt_scbp,
		    sizeof (struct scsi_status));

	} else {
		/*
		 * SCSI sense data is available and this command resulted in a
		 * CHECK CONDITION response.  Pass the sense data to the
		 * framework.
		 */
		struct scsi_arq_status *sts =
		    (struct scsi_arq_status *)pkt->pkt_scbp;

		/*
		 * The space allocated for the SCB may extend past the end of
		 * the "sts_sensedata".  Calculate the available space.
		 */
		size_t senselen = pkt->pkt_scblen -
		    offsetof(struct scsi_arq_status, sts_sensedata);

		/*
		 * We must only copy bytes that the device gave us, but also
		 * only as many as will fit in the buffer:
		 */
		size_t copylen = MIN(vsrq->vsrq_sense_len, senselen);

		/*
		 * Ensure any space we don't write to is cleared.
		 */
		bzero(pkt->pkt_scbp, pkt->pkt_scblen);

		/*
		 * Copy in the status byte and the sense data.
		 */
		bcopy(&vsrq->vsrq_status, &sts->sts_status,
		    sizeof (sts->sts_status));
		bcopy(&vsrq->vsrq_sense, &sts->sts_sensedata, copylen);

		/*
		 * Mock up a successful REQUEST SENSE:
		 */
		sts->sts_rqpkt_reason = CMD_CMPLT;
		sts->sts_rqpkt_resid = senselen - copylen;
		*((uchar_t *)&sts->sts_rqpkt_status) = STATUS_GOOD;
		sts->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
		sts->sts_rqpkt_statistics = 0;

		pkt->pkt_state |= STATE_ARQ_DONE;
	}

	mutex_exit(&vis->vis_mutex);
	scsi_hba_pkt_comp(pkt);
	mutex_enter(&vis->vis_mutex);
}

static int
vioscsi_poll_for(vioscsi_t *vis, vioscsi_cmd_t *vsc)
{
	VERIFY(MUTEX_HELD(&vis->vis_mutex));
	VERIFY(vsc->vsc_status & VIOSCSI_CMD_STATUS_POLLED);

	while (!(vsc->vsc_status & VIOSCSI_CMD_STATUS_POLL_COMPLETE)) {
		/*
		 * XXX Deal with expiry time.
		 */
		cv_wait(&vis->vis_cv_finish, &vis->vis_mutex);
	}

	/*
	 * Fire the completion callback for this command.  The callback is
	 * responsible for freeing the command, so it may not be referenced
	 * again once this call returns.
	 */
	vioscsi_process_finishq_one(vsc);

	return (0);
}

static void
vioscsi_discover(void *arg)
{
	vioscsi_t *vis = arg;
	uint32_t max_target;
	int r;

	mutex_enter(&vis->vis_mutex);
	vis->vis_status |= VIOSCSI_STATUS_DISCOVERY_RUNNING;
	vis->vis_status &= ~VIOSCSI_STATUS_DISCOVERY_REQUESTED;

	max_target = vis->vis_max_target;
	mutex_exit(&vis->vis_mutex);

	dev_err(vis->vis_dip, CE_WARN, "discovery START");

	/*
	 * Begin updating the target map.
	 */
	if (scsi_hba_tgtmap_set_begin(vis->vis_tgtmap) != DDI_SUCCESS) {
		dev_err(vis->vis_dip, CE_WARN, "failed to begin target map "
		    "observation on %s", VIOSCSI_IPORT);
		r = EIO;
		goto done;
	}

	/*
	 * XXX Primitive discovery loop.  We'll walk the full range of target
	 * addresses that we believe is possible, submitting REPORT LUNS to LUN
	 * zero at each target.  If that succeeds, we'll mark the target as
	 * active.
	 */
	for (uint32_t target = 0; target <= max_target; target++) {
		vioscsi_cmd_t *vsc;
		int res;

		if ((vsc = vioscsi_report_luns_alloc(vis, target)) == NULL) {
			r = ENOMEM;
			goto done;
		}

		mutex_enter(&vis->vis_mutex);
		vioscsi_q_push(vsc);
		res = vioscsi_poll_for(vis, vsc);
		mutex_exit(&vis->vis_mutex);

		if (res != 0) {
			dev_err(vis->vis_dip, CE_WARN,
			    "disco REPORT LUNS poll failure (%u) = %u",
			    target, res);
			r = EIO;
			vioscsi_cmd_free(vsc);
			goto done;
		}

		struct virtio_scsi_req_cmd_write *vsrq = virtio_dma_va(
		    vsc->vsc_dma, vsc->vsc_response_offset);
		if (vsrq->vsrq_response == VIRTIO_SCSI_S_OK) {
			/*
			 * Successful REPORT LUNS!  Mark this target as
			 * available.
			 * XXX Technically we should look _inside_ the REPORT
			 * LUNS response, rather than assume it's a disk on
			 * LUN 0?
			 */

			/*
			 * We use the same format for our address as is
			 * expected by devfsadm; see disk_callback_chan().
			 * XXX this is not quite true, it seems that SCSA will
			 * actually put the ",$lun" part on the end...
			 */
			char addr[128];
			(void) snprintf(addr, sizeof (addr), "%x",
			    target);

#if 0
			dev_err(vis->vis_dip, CE_WARN, "REPORT LUNS (%u) OK",
			    target);
#endif

			if (scsi_hba_tgtmap_set_add(vis->vis_tgtmap,
			    SCSI_TGT_SCSI_DEVICE, addr, NULL) != DDI_SUCCESS) {
				r = EIO;
				vioscsi_cmd_free(vsc);
				goto done;
			}
#if 0
		} else {
			dev_err(vis->vis_dip, CE_WARN, "REPORT LUNS (%u) FAIL",
			    target);
#endif
		}

		vioscsi_cmd_free(vsc);
	}

	r = 0;

done:
	if (r == 0) {
		dev_err(vis->vis_dip, CE_WARN, "discovery END OK");
		if (scsi_hba_tgtmap_set_end(vis->vis_tgtmap, 0) !=
		    DDI_SUCCESS) {
			dev_err(vis->vis_dip, CE_WARN, "target map update "
			    "failed");
			r = EIO;
		}
	} else {
		/*
		 * We were unable to complete a full scan, so abandon this
		 * target map update.
		 */
		dev_err(vis->vis_dip, CE_WARN, "discovery CANCEL");
		if (scsi_hba_tgtmap_set_flush(vis->vis_tgtmap) != DDI_SUCCESS) {
			dev_err(vis->vis_dip, CE_WARN, "target map update "
			    "cancel failed");
		}
	}

	mutex_enter(&vis->vis_mutex);
	vis->vis_status &= ~VIOSCSI_STATUS_DISCOVERY_RUNNING;
	if (r == 0) {
		/*
		 * Update the time of the last successful discovery:
		 */
		vis->vis_time_last_discovery = gethrtime();
	}

	/*
	 * If this discovery scan failed or if discovery was requested while we
	 * were already running, request a new discovery scan at the next
	 * periodic maintenance interval.
	 */
	if (r != 0 || (vis->vis_status & VIOSCSI_STATUS_DISCOVERY_REQUESTED)) {
		vis->vis_status |= VIOSCSI_STATUS_DISCOVERY_PERIODIC;
	}
	mutex_exit(&vis->vis_mutex);
}

static void
vioscsi_discover_request(vioscsi_t *vis)
{
	boolean_t run;
	VERIFY(MUTEX_HELD(&vis->vis_mutex));

	if (ddi_in_panic()) {
		return;
	}

	/*
	 * We only need to activate the discovery task queue if discovery is
	 * not in progress, and has not been scheduled for the periodic
	 * routine.
	 */
	run = (vis->vis_status & VIOSCSI_STATUS_DISCOVERY_MASK) == 0;
	vis->vis_status |= VIOSCSI_STATUS_DISCOVERY_REQUESTED;
	if (!run) {
		return;
	}

	if (ddi_taskq_dispatch(vis->vis_discover_taskq, vioscsi_discover,
	    vis, DDI_NOSLEEP) != DDI_SUCCESS) {
		/*
		 * We couldn't kick off the discovery task queue, so fall
		 * back to requesting discovery from the periodic routine.
		 */
		vis->vis_status |= VIOSCSI_STATUS_DISCOVERY_PERIODIC;
	}
}

void
vioscsi_periodic(void *arg)
{
	vioscsi_t *vis = arg;

	mutex_enter(&vis->vis_mutex);

	/*
	 * XXX Maintain!
	 */

	if (vioscsi_force_discovery) {
		dev_err(vis->vis_dip, CE_WARN, "FORCED DISCOVERY REQUEST...\n");
		vioscsi_force_discovery = 0;
		vioscsi_discover_request(vis);
	}

	if (vis->vis_status & VIOSCSI_STATUS_DISCOVERY_PERIODIC) {
		vis->vis_status &= ~VIOSCSI_STATUS_DISCOVERY_PERIODIC;

		vioscsi_discover_request(vis);
	}

	mutex_exit(&vis->vis_mutex);
}

static int
vioscsi_tran_setup_pkt(struct scsi_pkt *pkt, int (*callback)(caddr_t),
    caddr_t arg)
{
	struct scsi_device *sd;
	vioscsi_target_t *vist;
	vioscsi_t *vis;
	vioscsi_cmd_scsa_t *vscs;
	vioscsi_cmd_t *vsc;

	VERIFY((sd = scsi_address_device(&pkt->pkt_address)) != NULL);
	VERIFY((vist = scsi_device_hba_private_get(sd)) != NULL);
	VERIFY((vis = vist->vist_vioscsi) != NULL);
	VERIFY((vscs = (vioscsi_cmd_scsa_t *)pkt->pkt_ha_private) != NULL);

	if (pkt->pkt_cdblen > vis->vis_cdb_size) {
		dev_err(vis->vis_dip, CE_WARN, "oversize CDB: had %u, "
		    "needed %u", vis->vis_cdb_size, pkt->pkt_cdblen);
		return (-1);
	}

	/*
	 * The storage we allocate in the command itself will cover the
	 * outgoing command block, not including "datain", and the incoming
	 * response, not including "dataout".  The data space will come from
	 * cookies provided by SCSA.
	 */
	size_t sz = sizeof (struct virtio_scsi_req_cmd_read) +
	    vis->vis_cdb_size +
	    sizeof (struct virtio_scsi_req_cmd_write) +
	    vis->vis_sense_size;
	if ((vsc = vioscsi_cmd_alloc(vis, vis->vis_q_request, sz)) == NULL) {
		return (-1);
	}
	vsc->vsc_type = VIOSCSI_CMDTYPE_SCSA;
	vsc->vsc_scsa = vscs;
	vsc->vsc_response_offset = sizeof (struct virtio_scsi_req_cmd_read) +
	    vis->vis_cdb_size;
	vscs->vscs_cmd = vsc;
	vscs->vscs_pkt = pkt;

	/*
	 * XXX
	 */
	struct virtio_scsi_req_cmd_read *vsrq = virtio_dma_va(vsc->vsc_dma, 0);
	pkt->pkt_cdbp = &vsrq->vsrq_cdb[0];

	return (0);
}

static void
vioscsi_tran_teardown_pkt(struct scsi_pkt *pkt)
{
	vioscsi_cmd_scsa_t *vscs = (vioscsi_cmd_scsa_t *)pkt->pkt_ha_private;
	vioscsi_cmd_t *vsc = vscs->vscs_cmd;

	vioscsi_cmd_free(vsc);

	pkt->pkt_cdbp = NULL;
}

static int
vioscsi_tran_reset(struct scsi_address *ap, int level)
{
	/*
	 * XXX Pretend we did a reset.
	 */
	return (1);
}

static int
vioscsi_tran_abort(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	/*
	 * XXX Fail to abort anything right now.
	 */
	return (0);
}

static int
vioscsi_tran_start(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	struct scsi_device *sd;
	vioscsi_target_t *vist;
	vioscsi_t *vis;
	vioscsi_cmd_t *vsc;
	vioscsi_cmd_scsa_t *vscs;

	VERIFY((sd = scsi_address_device(&pkt->pkt_address)) != NULL);
	VERIFY((vist = scsi_device_hba_private_get(sd)) != NULL);
	VERIFY((vis = vist->vist_vioscsi) != NULL);
	VERIFY((vscs = (vioscsi_cmd_scsa_t *)pkt->pkt_ha_private) != NULL);
	VERIFY((vsc = vscs->vscs_cmd) != NULL);

	virtio_chain_t *vic = vsc->vsc_chain;

	if (vsc->vsc_status & VIOSCSI_CMD_STATUS_TRAN_START) {
		/*
		 * We have already used this command structure once.  We'll
		 * need to clear it out so that we can set up the descriptors
		 * again from scratch.
		 */
		vioscsi_cmd_clear(vsc);
	}
	vsc->vsc_status |= VIOSCSI_CMD_STATUS_TRAN_START;

#if 0
	dev_err(vis->vis_dip, CE_WARN, "device %s tran_start opcode 0x%x",
	    scsi_device_unit_address(sd), (uint_t)pkt->pkt_cdbp[0]);
#endif

	if (pkt->pkt_flags & FLAG_NOINTR) {
		/*
		 * We must sleep and wait for the completion of this command.
		 */
		vsc->vsc_status |= VIOSCSI_CMD_STATUS_POLLED;
	}

	struct virtio_scsi_req_cmd_read *vsrq = virtio_dma_va(vsc->vsc_dma, 0);
	bcopy(vist->vist_lun, vsrq->vsrq_lun, 8);
	vsrq->vsrq_id = vis->vis_next_tag++;

	/*
	 * Add the device-readable request header in the first descriptor.
	 */
	if (virtio_chain_append(vic, virtio_dma_cookie_pa(vsc->vsc_dma, 0),
	    vsc->vsc_response_offset, VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
		return (TRAN_BADPKT);
	}

	/*
	 * Append any outbound cookies between the request and response
	 * descriptors.
	 */
	if (pkt->pkt_numcookies > 0 && (pkt->pkt_dma_flags & DDI_DMA_WRITE)) {
		for (uint_t n = 0; n < pkt->pkt_numcookies; n++) {
			if (virtio_chain_append(vic,
			    pkt->pkt_cookies[n].dmac_laddress,
			    pkt->pkt_cookies[n].dmac_size,
			    VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
				return (TRAN_BADPKT);
			}
		}
	}

	/*
	 * Add the device-writeable response header.
	 */
	if (virtio_chain_append(vic,
	    virtio_dma_cookie_pa(vsc->vsc_dma, 0) + vsc->vsc_response_offset,
	    virtio_dma_cookie_size(vsc->vsc_dma, 0) - vsc->vsc_response_offset,
	    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
		return (TRAN_BADPKT);
	}

	/*
	 * Append any inbound cookies after the response header.
	 */
	if (pkt->pkt_numcookies > 0 && (pkt->pkt_dma_flags & DDI_DMA_READ)) {
		for (uint_t n = 0; n < pkt->pkt_numcookies; n++) {
			if (virtio_chain_append(vic,
			    pkt->pkt_cookies[n].dmac_laddress,
			    pkt->pkt_cookies[n].dmac_size,
			    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
				return (TRAN_BADPKT);
			}
		}
	}

	/*
	 * Initialise the SCSI packet as described in tran_start(9E).  We will
	 * progressively update these fields as the command moves through the
	 * submission and completion states.
	 */
	pkt->pkt_resid = 0;
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_statistics = 0;
	pkt->pkt_state = 0;

	/*
	 * XXX pkt->pkt_time
	 */

	mutex_enter(&vis->vis_mutex);
	vioscsi_q_push(vsc);

	/*
	 * Update the SCSI packet to reflect submission of the command.
	 */
	pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD;

	if (pkt->pkt_flags & FLAG_NOINTR) {
		/*
		 * XXX poll
		 */
		vioscsi_poll_for(vis, vsc);
	}

	mutex_exit(&vis->vis_mutex);
	return (TRAN_ACCEPT);
}


static int
vioscsi_setcap(struct scsi_address *sa, char *cap, int value, int whom)
{
	int index;

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE) {
		return (-1);
	}

	if (whom == 0) {
		return (-1);
	}

	switch (index) {
	case SCSI_CAP_CDB_LEN:
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_SECTOR_SIZE:
	case SCSI_CAP_INITIATOR_ID:
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_RESET_NOTIFICATION:
	case SCSI_CAP_INTERCONNECT_TYPE:
		/*
		 * We do not support changing any capabilities at this time.
		 */
		return (0);

	default:
		/*
		 * The capability in question is not known to this driver.
		 */
		return (-1);
	}
}

static int
vioscsi_getcap(struct scsi_address *sa, char *cap, int whom)
{
	struct scsi_device *sd;
	vioscsi_target_t *vist;
	vioscsi_t *vis;
	int index;

	VERIFY((sd = scsi_address_device(sa)) != NULL);
	VERIFY((vist = scsi_device_hba_private_get(sd)) != NULL);
	VERIFY((vis = vist->vist_vioscsi) != NULL);

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE) {
		return (-1);
	}

	switch (index) {
	case SCSI_CAP_CDB_LEN:
		return (vis->vis_cdb_size);

	case SCSI_CAP_DMA_MAX:
		return ((int)vis->vis_hba_dma_attr.dma_attr_maxxfer);

	case SCSI_CAP_SECTOR_SIZE:
		if (vis->vis_hba_dma_attr.dma_attr_granular > INT_MAX) {
			return (-1);
		}
		return ((int)vis->vis_hba_dma_attr.dma_attr_granular);

	case SCSI_CAP_INTERCONNECT_TYPE:
		/*
		 * Virtio SCSI devices are identified by a simple (target, lun)
		 * pair.  So that devfsadm does not expect a full SAS WWN,
		 * identify as a simple SCSI bus for this device.
		 */
		return (INTERCONNECT_PARALLEL);

	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		/*
		 * These capabilities are supported by the driver and the
		 * controller.  See scsi_ifgetcap(9F) for more information.
		 */
		return (1);

	case SCSI_CAP_INITIATOR_ID:
	case SCSI_CAP_RESET_NOTIFICATION:
		/*
		 * These capabilities are not supported.
		 */
		return (0);

	default:
		return (-1);
	}
}

static int
vioscsi_no_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
#if 0
	dev_err(hba_dip, CE_WARN, "vioscsi_no_tran_tgt_init called; "
	    "hba %s%d, target %s%d",
	    ddi_get_name(hba_dip), ddi_get_instance(hba_dip),
	    ddi_get_name(tgt_dip), ddi_get_instance(tgt_dip));
#endif
	return (DDI_FAILURE);
}

static int
vioscsi_no_tran_start(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	return (TRAN_BADPKT);
}

static int
vioscsi_hba_setup(vioscsi_t *vis)
{
	scsi_hba_tran_t *tran;

	if ((tran = scsi_hba_tran_alloc(vis->vis_dip, SCSI_HBA_CANSLEEP)) ==
	    NULL) {
		dev_err(vis->vis_dip, CE_WARN, "could not allocate SCSA "
		    "resources");
		return (DDI_FAILURE);
	}

	vis->vis_hba_tran = tran;
	tran->tran_hba_private = vis;

	tran->tran_tgt_init = vioscsi_no_tran_tgt_init;
	tran->tran_tgt_probe = scsi_hba_probe;

	tran->tran_start = vioscsi_no_tran_start;

	tran->tran_getcap = vioscsi_getcap;
	tran->tran_setcap = vioscsi_setcap;

	tran->tran_setup_pkt = vioscsi_tran_setup_pkt;
	tran->tran_teardown_pkt = vioscsi_tran_teardown_pkt;
	tran->tran_hba_len = sizeof (vioscsi_cmd_scsa_t);
	tran->tran_interconnect_type = INTERCONNECT_SAS;

	VERIFY3U(vis->vis_hba_dma_attr.dma_attr_sgllen, !=, 0);
	if (scsi_hba_attach_setup(vis->vis_dip, &vis->vis_hba_dma_attr,
	    tran, SCSI_HBA_HBA | SCSI_HBA_ADDR_COMPLEX | SCSI_HBA_TRAN_SCB) !=
	    DDI_SUCCESS) {
		dev_err(vis->vis_dip, CE_WARN,
		    "could not attach to SCSA framework");
		scsi_hba_tran_free(tran);
		return (DDI_FAILURE);
	}

	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_SCSA);
	return (DDI_SUCCESS);
}

static void
vioscsi_hba_teardown(vioscsi_t *vis)
{
	if (!INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_SCSA)) {
		return;
	}

	VERIFY(scsi_hba_detach(vis->vis_dip) != DDI_FAILURE);
	scsi_hba_tran_free(vis->vis_hba_tran);
	INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_SCSA);
}

static boolean_t
vioscsi_addr_parse(const char *ua, uint_t *targetp, uint_t *lunp)
{
	long target, lun;
	const char *comma;
	char *eptr;

	if ((comma = strchr(ua, ',')) == NULL) {
		return (B_FALSE);
	}

	if (ddi_strtol(ua, &eptr, 16, &target) != 0 || eptr != comma ||
	    target < 0 || target > UINT8_MAX) {
		return (B_FALSE);
	}

	if (ddi_strtol(comma + 1, &eptr, 16, &lun) != 0 || *eptr != '\0' ||
	    lun < 0 || lun > UINT16_MAX) {
		return (B_FALSE);
	}

	if (targetp != NULL) {
		*targetp = (uint_t)target;
	}
	if (lunp != NULL) {
		*lunp = (uint_t)lun;
	}
	return (B_TRUE);
}

static void
vioscsi_tgtmap_activate(void *arg, char *addr, scsi_tgtmap_tgt_type_t type,
    void **privpp)
{
#if 0
	vioscsi_t *vis = arg;
#endif

	VERIFY3S(type, ==, SCSI_TGT_SCSI_DEVICE);
	// XXX ... VERIFY(vioscsi_addr_parse(addr, NULL, NULL));

	/*
	 * XXX more validation?
	 */
}

boolean_t
vioscsi_tgtmap_deactivate(void *arg, char *addr,
    scsi_tgtmap_tgt_type_t type, void *priv, scsi_tgtmap_deact_rsn_t reason)
{
	VERIFY3S(type, ==, SCSI_TGT_SCSI_DEVICE);
	// XXX ... VERIFY(vioscsi_addr_parse(addr, NULL, NULL));

	/*
	 * XXX more validation?
	 */

	return (B_FALSE);
}

static int
vioscsi_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	vioscsi_t *vis = (vioscsi_t *)hba_tran->tran_hba_private;
	const char *ua;
	uint_t target, lun;

	/*
	 * Convert the unit address string back into a target and LUN number.
	 */
	if ((ua = scsi_device_unit_address(sd)) == NULL ||
	    !vioscsi_addr_parse(ua, &target, &lun)) {
		dev_err(vis->vis_dip, CE_WARN, "vioscsi_tran_tgt_init: "
		    "ua \"%s\" invalid",
		    (ua == NULL) ? "<NULL>" : ua);
		return (DDI_FAILURE);
	}

	vioscsi_target_t *vist;
	if ((vist = kmem_zalloc(sizeof (*vist), KM_NOSLEEP)) == NULL) {
		dev_err(vis->vis_dip, CE_WARN, "could not allocate target "
		    "object due to memory exhaustion");
		return (DDI_FAILURE);
	}

	mutex_enter(&vis->vis_mutex);
	if (vis->vis_status & VIOSCSI_STATUS_DETACHING) {
		/*
		 * We are detaching.  Do not accept any more requests to
		 * attach targets from the framework.
		 */
		mutex_exit(&vis->vis_mutex);
		kmem_free(vist, sizeof (*vist));
		return (DDI_FAILURE);
	}

	vist->vist_vioscsi = vis;
	vist->vist_scsi_dev = sd;
	VERIFY3P(sd->sd_dev, ==, tgt_dip);

	/*
	 * As per the specification, the first LUN address byte is 1, followed
	 * by the target, then a 2-byte logical unit.
	 * XXX It's really not clear if they mean the LUN to be LE16...
	 */
	vist->vist_lun[0] = 0x01;
	vist->vist_lun[1] = target & 0xFF;
	vist->vist_lun[2] = lun & 0xFF;
	vist->vist_lun[3] = (lun >> 8) && 0xFF;

	/*
	 * XXX Link this target object to the controller.
	 */

	scsi_device_hba_private_set(sd, vist);

	mutex_exit(&vis->vis_mutex);
	return (DDI_SUCCESS);
}

static void
vioscsi_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	vioscsi_t *vis = (vioscsi_t *)hba_tran->tran_hba_private;
	vioscsi_target_t *vist = scsi_device_hba_private_get(sd);

	VERIFY3P(vist->vist_scsi_dev, ==, sd);

	mutex_enter(&vis->vis_mutex);
	/*
	 * XXX remove from controller target list.
	 */
	mutex_exit(&vis->vis_mutex);

	scsi_device_hba_private_set(sd, NULL);

	kmem_free(vist, sizeof (*vist));
}

static int
vioscsi_iport_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	const char *addr;
	vioscsi_t *vis;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	VERIFY((addr = scsi_hba_iport_unit_address(dip)) != NULL);

	/*
	 * We cannot get to our parent via the tran_hba_private member.  This
	 * member is reset to NULL when the scsi_hba_tran_t structure is
	 * duplicated for the iport-specific copy.
	 */
	VERIFY((vis = ddi_get_soft_state(vioscsi_state,
	    ddi_get_instance(ddi_get_parent(dip)))) != NULL);

	if (strcmp(addr, VIOSCSI_IPORT) != 0) {
		/*
		 * We only support the one hard-coded iport for now.
		 */
		return (DDI_FAILURE);
	}

	scsi_hba_tran_t *tran;
	if ((tran = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	tran->tran_tgt_init = vioscsi_tran_tgt_init;
	tran->tran_tgt_free = vioscsi_tran_tgt_free;

	tran->tran_start = vioscsi_tran_start;
	tran->tran_reset = vioscsi_tran_reset;
	tran->tran_abort = vioscsi_tran_abort;

	tran->tran_hba_private = vis;

	mutex_enter(&vis->vis_mutex);

	if (scsi_hba_tgtmap_create(dip, SCSI_TM_FULLSET, MICROSEC, 2 * MICROSEC,
	    vis, vioscsi_tgtmap_activate, vioscsi_tgtmap_deactivate,
	    &vis->vis_tgtmap) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * XXX SCHEDULE A DISCOVERY REQUEST NOW...
	 */
	vioscsi_discover_request(vis);

	vis->vis_iport = dip;

	mutex_exit(&vis->vis_mutex);
	return (DDI_SUCCESS);
}

static int
vioscsi_iport_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	char *addr;
	scsi_hba_tran_t *tran;
	vioscsi_t *vis;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	VERIFY((tran = ddi_get_driver_private(dip)) != NULL);
	VERIFY((vis = tran->tran_hba_private) != NULL);

	VERIFY((addr = scsi_hba_iport_unit_address(dip)) != NULL);

	if (strcmp(addr, VIOSCSI_IPORT) != 0) {
		/*
		 * We only support one hard-coded iport for now.
		 */
		return (DDI_FAILURE);
	}

	/*
	 * XXX TAKE LOCK
	 */

	if (vis->vis_tgtmap != NULL) {
		scsi_hba_tgtmap_t *t = vis->vis_tgtmap;
		vis->vis_tgtmap = NULL;

		/*
		 * XXX DROP LOCK.
		 */
		scsi_hba_tgtmap_destroy(t);
		/*
		 * XXX TAKE LOCK
		 */
	}

	vis->vis_iport = NULL;

	/*
	 * XXX DROP LOCK
	 */

	return (DDI_SUCCESS);
}

static int
vioscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	uint32_t instance;
	vioscsi_t *vis;
	virtio_t *vio;
	int r;

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (vioscsi_iport_attach(dip, cmd));
	}

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/*
	 * Allocate the per-controller soft state object and get a pointer to
	 * it.
	 */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(vioscsi_state, instance) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not allocate soft state");
		return (DDI_FAILURE);
	}
	if ((vis = ddi_get_soft_state(vioscsi_state, instance)) == NULL) {
		dev_err(dip, CE_WARN, "could not get soft state");
		ddi_soft_state_free(vioscsi_state, instance);
		return (DDI_FAILURE);
	}
	vis->vis_dip = dip;
	vis->vis_instance = instance;
	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_BASIC);

	/*
	 * Common Virtio initialisation.
	 */
	if ((vio = virtio_init(dip, VIRTIO_SCSI_F_HOTPLUG, B_TRUE)) == NULL) {
		goto fail;
	}
	vis->vis_virtio = vio;
	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_VIRTIO);

	/*
	 * XXX I believe this should be used to constrain the number of chained
	 * descriptors to use for a command.
	 */
	vis->vis_seg_max = virtio_dev_get32(vio, VIRTIO_SCSI_CFG_SEG_MAX);
	dev_err(dip, CE_WARN, "config: seg_max = %u", vis->vis_seg_max);

	vis->vis_hba_dma_attr = vioscsi_dma_attr;
	vis->vis_hba_dma_attr.dma_attr_sgllen = vis->vis_seg_max - 2;

	/*
	 * The SCSI device has several virtqueues:
	 *
	 *	0	control queue
	 *	1	event queue
	 *	2..n	request queue(s)
	 *
	 * The control and event queues have a constrained size and shape in
	 * terms of DMA resources, so we'll force the use of direct descriptors
	 * there even if the host supports indirect descriptors.  The I/O
	 * request queue can theoretically support much longer scatter-gather
	 * lists; if the device supports indirect descriptors we'll try them
	 * there.
	 */
	if ((vis->vis_q_control = virtio_queue_alloc(vio,
	    VIRTIO_SCSI_VIRTQ_CONTROL, "control", vioscsi_handle_control,
	    vis, B_TRUE, 2)) == NULL ||
	    (vis->vis_q_event = virtio_queue_alloc(vio,
	    VIRTIO_SCSI_VIRTQ_EVENT, "event", vioscsi_handle_event,
	    vis, B_TRUE, 1)) == NULL ||
	    (vis->vis_q_request = virtio_queue_alloc(vio,
	    VIRTIO_SCSI_VIRTQ_REQUEST, "request", vioscsi_handle_request,
	    vis, B_FALSE, vis->vis_seg_max)) == NULL) {
		dev_err(dip, CE_WARN, "failed to allocate virtqueues");
		goto fail;
	}

	if (virtio_init_complete(vio, 0) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to complete Virtio init");
		goto fail;
	}

	/*
	 * Now that we have the correct interrupt priority, we can initialise
	 * the mutex.  This must be done before the interrupt handler is
	 * enabled.
	 */
	mutex_init(&vis->vis_mutex, NULL, MUTEX_DRIVER, virtio_intr_pri(vio));
	cv_init(&vis->vis_cv_finish, NULL, CV_DRIVER, NULL);
	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_MUTEX);

	/*
	 * Read some device configuration properties.
	 */
	uint32_t num_queues = virtio_dev_get32(vio,
	    VIRTIO_SCSI_CFG_NUM_QUEUES);
	dev_err(dip, CE_WARN, "config: num_queues = %u", num_queues);

	vis->vis_event_info_size = virtio_dev_get32(vio,
	    VIRTIO_SCSI_CFG_EVENT_INFO_SIZE);
	dev_err(dip, CE_WARN, "config: event_info_size = %u",
	    vis->vis_event_info_size);

	vis->vis_sense_size = virtio_dev_get32(vio,
	    VIRTIO_SCSI_CFG_SENSE_SIZE);
	dev_err(dip, CE_WARN, "config: sense_size = %u", vis->vis_sense_size);

	vis->vis_cdb_size = virtio_dev_get32(vio,
	    VIRTIO_SCSI_CFG_CDB_SIZE);
	dev_err(dip, CE_WARN, "config: cdb_size = %u", vis->vis_cdb_size);

	/*
	 * The specification suggests the maximum channel value SHOULD be zero.
	 * At least one implementation in the wild returns a value of one.
	 * It's not clear from the specification how one would actually include
	 * a channel number in the described LUN address format, so for now
	 * just report if the value is outside the range we've seen.
	 */
	vis->vis_max_channel = virtio_dev_get16(vio,
	    VIRTIO_SCSI_CFG_MAX_CHANNEL);
	if (vis->vis_max_channel > 1) {
		/*
		 * We don't need to clamp because we don't actually use this
		 * value for anything.
		 */
		dev_err(dip, CE_WARN, "max_channel value of %u is higher "
		    "than expected", vis->vis_max_channel);
	}

	/*
	 * The specification suggests that the maximum target number should be
	 * capped at 255.  We'll clamp at that value in order to avoid an even
	 * more expensive scan than usual.
	 */
	vis->vis_max_target_raw = virtio_dev_get16(vio,
	    VIRTIO_SCSI_CFG_MAX_TARGET);
	if (vis->vis_max_target_raw > 255) {
		vis->vis_max_target = 255;
		dev_err(dip, CE_WARN, "max_target value was %u, clamping at "
		    "%u", vis->vis_max_target_raw, vis->vis_max_target);
	} else {
		vis->vis_max_target = vis->vis_max_target_raw;
	}

	/*
	 * The maximum LUN number should be capped at 16383 according to the
	 * specification.  In practice, it seems that most implementations will
	 * just use LUN 0 on each target.
	 */
	vis->vis_max_lun_raw = virtio_dev_get16(vio,
	    VIRTIO_SCSI_CFG_MAX_LUN);
	if (vis->vis_max_lun_raw > 1) {
		vis->vis_max_lun = 1;
		dev_err(dip, CE_WARN, "max_lun value was %u, clamping at "
		    "%u", vis->vis_max_lun_raw, vis->vis_max_lun);
	} else {
		vis->vis_max_lun = vis->vis_max_lun_raw;
	}

	/*
	 * Register the maintenance routine for periodic execution:
	 */
	vis->vis_periodic = ddi_periodic_add(vioscsi_periodic, vis,
	    VIOSCSI_PERIODIC_RATE * NANOSEC, DDI_IPL_0);
	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_PERIODIC);

	/*
	 * Create a task queue to manage the discovery of targets and LUNs.
	 */
	char taskq_name[64];
	(void) snprintf(taskq_name, sizeof (taskq_name), "vioscsi_discover_%u",
	    instance);
	if ((vis->vis_discover_taskq = ddi_taskq_create(dip, taskq_name, 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		dev_err(dip, CE_WARN, "failed to create discovery task queue");
		goto fail;
	}
	INITLEVEL_SET(vis, VIOSCSI_INITLEVEL_TASKQ);

	/*
	 * Populate the event virtqueue with some buffers so that the host can
	 * notify us of topology changes.  This is done prior to the first
	 * probe for targets so that we don't miss any topology changes.
	 */
	(void) vioscsi_fill_events(vis); /* XXX */

	if (virtio_interrupts_enable(vio) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not enable interrupts");
		goto fail;
	}

	if (vioscsi_hba_setup(vis) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "SCSI framework setup failed");
		goto fail;
	}

	if (scsi_hba_iport_register(dip, VIOSCSI_IPORT) != DDI_SUCCESS) {
		goto fail;
	}

	/*
	 * Announce the attachment of this controller.
	 */
	ddi_report_dev(dip);
	dev_err(dip, CE_WARN, "attach ok");

	return (DDI_SUCCESS);

fail:
	vioscsi_cleanup(vis, B_TRUE);
	return (DDI_FAILURE);
}

static void
vioscsi_cleanup(vioscsi_t *vis, boolean_t failed)
{
	/*
	 * XXX reset the device first, to try and prevent it from doing
	 * anything else to our DMA memory.
	 */

	/*
	 * XXX before we free these queues, we need to claw back the contents
	 * of, e.g., the "event" queue -- it has a number of outstanding
	 * descriptors in it so that the device can inform us of asynchronous
	 * events.  I believe we need to reset the device, then ... free the
	 * virtqueue?  We probably need a special entrypoint for this...
	 */
#if 0
	vioscsi_q_fini(&vis->vis_q_control);
	vioscsi_q_fini(&vis->vis_q_event);
	vioscsi_q_fini(&vis->vis_q_request);
#endif

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_TASKQ)) {
		ddi_taskq_destroy(vis->vis_discover_taskq);
		vis->vis_discover_taskq = NULL;

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_TASKQ);
	}

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_PERIODIC)) {
		ddi_periodic_delete(vis->vis_periodic);

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_PERIODIC);
	}

	vioscsi_hba_teardown(vis);

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_VIRTIO)) {
		virtio_fini(vis->vis_virtio, failed);

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_VIRTIO);
	}

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_BASIC)) {

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_BASIC);
	}

	if (INITLEVEL_ACTIVE(vis, VIOSCSI_INITLEVEL_MUTEX)) {
		mutex_destroy(&vis->vis_mutex);
		cv_destroy(&vis->vis_cv_finish);

		INITLEVEL_CLEAR(vis, VIOSCSI_INITLEVEL_MUTEX);
	}

	VERIFY0(vis->vis_init_level);

	ddi_soft_state_free(vioscsi_state, ddi_get_instance(vis->vis_dip));
}

static int
vioscsi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	scsi_hba_tran_t *tran = ddi_get_driver_private(dip);
	vioscsi_t *vis = (vioscsi_t *)tran->tran_hba_private;

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (vioscsi_iport_detach(dip, cmd));
	}

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	mutex_enter(&vis->vis_mutex);
	if (vis->vis_iport != NULL) {
		mutex_exit(&vis->vis_mutex);
		dev_err(vis->vis_dip, CE_WARN, "cannot detach: iports still "
		    "attached");
		return (DDI_FAILURE);
	}

	vis->vis_status |= VIOSCSI_STATUS_DETACHING;
	mutex_exit(&vis->vis_mutex);

	vioscsi_cleanup(vis, B_FALSE);

	dev_err(dip, CE_WARN, "detach ok");
	return (DDI_SUCCESS);
}

static int
vioscsi_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rval)
{
	int inst = MINOR2INST(getminor(dev));
	int status;

	if (secpolicy_sys_config(credp, B_FALSE) != 0) {
		return (EPERM);
	}

	if (ddi_get_soft_state(vioscsi_state, inst) == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	default:
		status = scsi_hba_ioctl(dev, cmd, arg, mode, credp, rval);
		break;
	}

	return (status);
}
