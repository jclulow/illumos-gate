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


vioscsi_cmd_t *
vioscsi_cmd_alloc(vioscsi_t *vis, virtio_queue_t *viq, size_t sz)
{
	int kmflags = KM_SLEEP;

	vioscsi_cmd_t *vsc;
	if ((vsc = kmem_zalloc(sizeof (*vsc), kmflags)) == NULL) {
		return (NULL);
	}
	vsc->vsc_vioscsi = vis;
	vsc->vsc_q = viq;

	if ((vsc->vsc_dma = virtio_dma_alloc(vis->vis_virtio, sz,
	    &vioscsi_dma_attr, DDI_DMA_CONSISTENT | DDI_DMA_RDWR,
	    kmflags)) == NULL) {
		kmem_free(vsc, sizeof (*vsc));
		return (NULL);
	}
	bzero(virtio_dma_va(vsc->vsc_dma, 0), sz);

	if ((vsc->vsc_chain = virtio_chain_alloc(viq, kmflags)) == NULL) {
		virtio_dma_free(vsc->vsc_dma);
		kmem_free(vsc, sizeof (*vsc));
		return (NULL);
	}
	virtio_chain_data_set(vsc->vsc_chain, vsc);

	return (vsc);
}

void
vioscsi_cmd_free(vioscsi_cmd_t *vsc)
{
	virtio_chain_free(vsc->vsc_chain);
	virtio_dma_free(vsc->vsc_dma);
	kmem_free(vsc, sizeof (*vsc));
}

void
vioscsi_cmd_clear(vioscsi_cmd_t *vsc)
{
	VERIFY(!(vsc->vsc_status & VIOSCSI_CMD_STATUS_INFLIGHT));
	vsc->vsc_status = 0; /* XXX */

	virtio_chain_clear(vsc->vsc_chain);
}

void
vioscsi_q_push(vioscsi_cmd_t *vsc)
{
	vioscsi_t *vis = vsc->vsc_vioscsi;
	virtio_t *vio = vis->vis_virtio;

	VERIFY(MUTEX_HELD(&vis->vis_mutex));

	VERIFY(!(vsc->vsc_status & VIOSCSI_CMD_STATUS_INFLIGHT));
	vsc->vsc_status |= VIOSCSI_CMD_STATUS_INFLIGHT;

	virtio_dma_sync(vsc->vsc_dma, DDI_DMA_SYNC_FORDEV);

	vsc->vsc_time_push = gethrtime();
	virtio_chain_submit(vsc->vsc_chain, B_TRUE);
}

vioscsi_cmd_t *
vioscsi_q_pull(vioscsi_t *vis, virtio_queue_t *viq)
{
	virtio_chain_t *vic;

	VERIFY(MUTEX_HELD(&vis->vis_mutex));

	if ((vic = virtio_queue_poll(viq)) == NULL) {
		return (NULL);
	}

	vioscsi_cmd_t *vsc = virtio_chain_data(vic);
	VERIFY(vsc != NULL);
	VERIFY3P(vsc->vsc_chain, ==, vic);

	VERIFY(vsc->vsc_status & VIOSCSI_CMD_STATUS_INFLIGHT);
	vsc->vsc_status &= ~VIOSCSI_CMD_STATUS_INFLIGHT;

	virtio_dma_sync(vsc->vsc_dma, DDI_DMA_SYNC_FORCPU);

	return (vsc);
}
