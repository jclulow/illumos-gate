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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * VIRTIO 9P DRIVER
 *
 * This driver provides support for Virtio 9P devices.  Each driver instance
 * attaches to a single underlying 9P channel.  A 9P file system will use LDI
 * to open this device.
 */

#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/containerof.h>
#include <sys/ctype.h>
#include <sys/stdbool.h>
#include <sys/sysmacros.h>
#include <sys/list.h>

#include "virtio.h"
#include "vio9p_impl.h"

static void *vio9p_state;

uint_t vio9p_int_handler(caddr_t, caddr_t);
static uint_t vio9p_poll(vio9p_t *);
static int vio9p_quiesce(dev_info_t *);
static int vio9p_attach(dev_info_t *, ddi_attach_cmd_t);
static int vio9p_detach(dev_info_t *, ddi_detach_cmd_t);
static int vio9p_open(dev_t *, int, int, cred_t *);
static int vio9p_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int vio9p_close(dev_t, int, int, cred_t *);
static int vio9p_read(dev_t, uio_t *, cred_t *);
static int vio9p_write(dev_t, uio_t *, cred_t *);
static vio9p_req_t *vio9p_req_alloc_impl(vio9p_t *, int);
static void vio9p_req_free_impl(vio9p_t *, vio9p_req_t *);

static struct cb_ops vio9p_cb_ops = {
	.cb_rev =			CB_REV,
	.cb_flag =			D_NEW | D_MP,

	.cb_open =			vio9p_open,
	.cb_close =			vio9p_close,
	.cb_read =			vio9p_read,
	.cb_write =			vio9p_write,
	.cb_ioctl =			vio9p_ioctl,

	.cb_strategy =			nodev,
	.cb_print =			nodev,
	.cb_dump =			nodev,
	.cb_devmap =			nodev,
	.cb_mmap =			nodev,
	.cb_segmap =			nodev,
	.cb_chpoll =			nochpoll,
	.cb_prop_op =			ddi_prop_op,
	.cb_str =			NULL,
	.cb_aread =			nodev,
	.cb_awrite =			nodev,
};

static struct dev_ops vio9p_dev_ops = {
	.devo_rev =			DEVO_REV,
	.devo_refcnt =			0,

	.devo_attach =			vio9p_attach,
	.devo_detach =			vio9p_detach,
	.devo_quiesce =			vio9p_quiesce,

	.devo_cb_ops =			&vio9p_cb_ops,

	.devo_getinfo =			ddi_no_info,
	.devo_identify =		nulldev,
	.devo_probe =			nulldev,
	.devo_reset =			nodev,
	.devo_bus_ops =			NULL,
	.devo_power =			NULL,
};

static struct modldrv vio9p_modldrv = {
	.drv_modops =			&mod_driverops,
	.drv_linkinfo =			"VIRTIO 9P driver",
	.drv_dev_ops =			&vio9p_dev_ops
};

static struct modlinkage vio9p_modlinkage = {
	.ml_rev =			MODREV_1,
	.ml_linkage =			{ &vio9p_modldrv, NULL }
};

/*
 * DMA attribute template for header and status blocks.
 */
static const ddi_dma_attr_t vio9p_dma_attr = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x0000000000000000,
	.dma_attr_addr_hi =		0xFFFFFFFFFFFFFFFF,
	.dma_attr_count_max =		0x00000000FFFFFFFF,
	.dma_attr_align =		1,
	.dma_attr_burstsizes =		1,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0x00000000FFFFFFFF,
	.dma_attr_seg =			0x00000000FFFFFFFF,
	.dma_attr_sgllen =		1,
	.dma_attr_granular =		1,
	.dma_attr_flags =		0
};

uint_t
vio9p_int_handler(caddr_t arg0, caddr_t arg1)
{
	vio9p_t *vin = (vio9p_t *)arg0;

	mutex_enter(&vin->vin_mutex);
	(void) vio9p_poll(vin);
	mutex_exit(&vin->vin_mutex);

	return (DDI_INTR_CLAIMED);
}

static bool
vio9p_req_freelist_put(vio9p_t *vin, vio9p_req_t *vnr)
{
	VERIFY(!list_link_active(&vnr->vnr_link_complete));
	VERIFY(!list_link_active(&vnr->vnr_link_free));

	if (vin->vin_req_nfreelist < VIRTIO_9P_MAX_FREELIST) {
		vin->vin_generation = 0;
		list_insert_head(&vin->vin_req_freelist, vnr);
		vin->vin_req_nfreelist++;
		return (true);
	}

	return (false);
}

static void
vio9p_req_free(vio9p_t *vin, vio9p_req_t *vnr)
{
	VERIFY(MUTEX_HELD(&vin->vin_mutex));

	if (list_link_active(&vnr->vnr_link_complete)) {
		list_remove(&vin->vin_completes, vnr);
	}

	if (vio9p_req_freelist_put(vin, vnr)) {
		/*
		 * The freelist is not full, so we don't need to fully tear
		 * this down.
		 */
		return;
	}

	vio9p_req_free_impl(vin, vnr);
}

static void
vio9p_req_free_impl(vio9p_t *vin, vio9p_req_t *vnr)
{
	if (vnr->vnr_chain != NULL) {
		virtio_chain_free(vnr->vnr_chain);
		vnr->vnr_chain = NULL;
	}
	if (vnr->vnr_dma_in != NULL) {
		virtio_dma_free(vnr->vnr_dma_in);
		vnr->vnr_dma_in = NULL;
	}
	if (vnr->vnr_dma_out != NULL) {
		virtio_dma_free(vnr->vnr_dma_out);
		vnr->vnr_dma_out = NULL;
	}

	list_remove(&vin->vin_reqs, vnr);
	kmem_free(vnr, sizeof (*vnr));
}

static vio9p_req_t *
vio9p_req_alloc(vio9p_t *vin, int kmflag)
{
	vio9p_req_t *vnr;

	VERIFY(MUTEX_HELD(&vin->vin_mutex));

	/*
	 * Try the free list first:
	 */
	if ((vnr = list_remove_head(&vin->vin_req_freelist)) != NULL) {
		VERIFY(vin->vin_req_nfreelist > 0);
		vin->vin_req_nfreelist--;
		return (vnr);
	}

	return (vio9p_req_alloc_impl(vin, kmflag));
}

static vio9p_req_t *
vio9p_req_alloc_impl(vio9p_t *vin, int kmflag)
{
	dev_info_t *dip = vin->vin_dip;
	vio9p_req_t *vnr;

	if ((vnr = kmem_zalloc(sizeof (*vnr), kmflag)) == NULL) {
		return (NULL);
	}
	list_insert_tail(&vin->vin_reqs, vnr);

	if ((vnr->vnr_chain = virtio_chain_alloc(vin->vin_vq, kmflag)) ==
	    NULL) {
		dev_err(vin->vin_dip, CE_WARN, "chain alloc failure");
		goto fail;
	}
	virtio_chain_data_set(vnr->vnr_chain, vnr);

	/*
	 * Allocate outbound request buffer:
	 */
	if ((vnr->vnr_dma_out = virtio_dma_alloc(vin->vin_virtio,
	    VIRTIO_9P_REQ_SIZE, &vio9p_dma_attr,
	    DDI_DMA_CONSISTENT | DDI_DMA_WRITE, kmflag)) == NULL) {
		dev_err(dip, CE_WARN, "DMA out alloc failure");
		goto fail;
	}
	VERIFY3U(virtio_dma_ncookies(vnr->vnr_dma_out), ==, 1);

	if (virtio_chain_append(vnr->vnr_chain,
	    virtio_dma_cookie_pa(vnr->vnr_dma_out, 0),
	    virtio_dma_cookie_size(vnr->vnr_dma_out, 0),
	    VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "chain append out failure");
		goto fail;
	}

	/*
	 * Allocate inbound request buffer:
	 */
	if ((vnr->vnr_dma_in = virtio_dma_alloc(vin->vin_virtio,
	    VIRTIO_9P_REQ_SIZE, &vio9p_dma_attr,
	    DDI_DMA_CONSISTENT | DDI_DMA_READ, kmflag)) == NULL) {
		dev_err(dip, CE_WARN, "DMA in alloc failure");
		goto fail;
	}
	VERIFY3U(virtio_dma_ncookies(vnr->vnr_dma_in), ==, 1);

	if (virtio_chain_append(vnr->vnr_chain,
	    virtio_dma_cookie_pa(vnr->vnr_dma_in, 0),
	    virtio_dma_cookie_size(vnr->vnr_dma_in, 0),
	    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "chain append in failure");
		goto fail;
	}

	return (vnr);

fail:
	vio9p_req_free_impl(vin, vnr);
	return (NULL);
}

static uint_t
vio9p_poll(vio9p_t *vin)
{
	virtio_chain_t *vic;
	uint_t count = 0;
	bool wakeup = false;

	VERIFY(MUTEX_HELD(&vin->vin_mutex));

	while ((vic = virtio_queue_poll(vin->vin_vq)) != NULL) {
		vio9p_req_t *vnr = virtio_chain_data(vic);

		count++;

		virtio_dma_sync(vnr->vnr_dma_in, DDI_DMA_SYNC_FORCPU);

		if (!vin->vin_open ||
		    vnr->vnr_generation != vin->vin_generation) {
			/*
			 * Either the device is not open, or the device has
			 * been closed and opened again since this request was
			 * submitted.  Just free the memory and drive on.
			 */
			vio9p_req_free(vin, vnr);
			continue;
		}

		list_insert_tail(&vin->vin_completes, vnr);
		wakeup = true;
	}

	if (wakeup) {
		cv_broadcast(&vin->vin_cv);
	}

	return (count);
}

static int
vio9p_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	virtio_t *vio;
	vio9p_req_t *vnr;
	boolean_t did_mutex = B_FALSE;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(vio9p_state, instance) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if ((vio = virtio_init(dip, VIRTIO_9P_WANTED_FEATURES, B_TRUE)) ==
	    NULL) {
		ddi_soft_state_free(vio9p_state, instance);
		dev_err(dip, CE_WARN, "failed to start Virtio init");
		return (DDI_FAILURE);
	}

	vio9p_t *vin = ddi_get_soft_state(vio9p_state, instance);
	vin->vin_dip = dip;
	vin->vin_virtio = vio;
	ddi_set_driver_private(dip, vin);
	list_create(&vin->vin_reqs, sizeof (vio9p_req_t),
	    offsetof(vio9p_req_t, vnr_link));
	list_create(&vin->vin_completes, sizeof (vio9p_req_t),
	    offsetof(vio9p_req_t, vnr_link_complete));
	list_create(&vin->vin_req_freelist, sizeof (vio9p_req_t),
	    offsetof(vio9p_req_t, vnr_link_free));

	if (virtio_feature_present(vio, VIRTIO_9P_F_MOUNT_TAG)) {
		uint16_t len = virtio_dev_get16(vio, VIRTIO_9P_CONFIG_TAG_SZ);
		if (len >= VIRTIO_9P_TAGLEN) {
			len = VIRTIO_9P_TAGLEN;
		}

		for (uint16_t n = 0; n < len; n++) {
			vin->vin_tag[n] = virtio_dev_get8(vio,
			    VIRTIO_9P_CONFIG_TAG + n);
		}
	}

	/*
	 * When allocating the request queue, we include two additional
	 * descriptors (beyond those required for request data) to account for
	 * the header and the status byte.
	 */
	if ((vin->vin_vq = virtio_queue_alloc(vio, VIRTIO_9P_VIRTQ_REQUESTS,
	    "requests", vio9p_int_handler, vin, B_FALSE, 2)) == NULL) {
		goto fail;
	}

	if (virtio_init_complete(vio, 0) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to complete Virtio init");
		goto fail;
	}

	/*
	 * Make sure the free list contains at least one request at attach time
	 * so that the device is always somewhat useable:
	 */
	if ((vnr = vio9p_req_alloc_impl(vin, KM_SLEEP)) == NULL) {
		dev_err(dip, CE_WARN, "failed to allocate first request");
		goto fail;
	}
	VERIFY(vio9p_req_freelist_put(vin, vnr));

	cv_init(&vin->vin_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&vin->vin_mutex, NULL, MUTEX_DRIVER, virtio_intr_pri(vio));
	did_mutex = B_TRUE;

	if (virtio_interrupts_enable(vio) != DDI_SUCCESS) {
		goto fail;
	}

	/*
	 * Hang out a minor node so that we can be opened.
	 */
	int minor = ddi_get_instance(dip);
	if (ddi_create_minor_node(dip, "9p", S_IFCHR, minor, DDI_PSEUDO,
	    0) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not create minor node");
		goto fail;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	ddi_remove_minor_node(dip, NULL);
	if (vio != NULL) {
		(void) virtio_fini(vio, B_TRUE);
	}
	if (did_mutex) {
		mutex_destroy(&vin->vin_mutex);
		cv_destroy(&vin->vin_cv);
	}
	while ((vnr = list_remove_head(&vin->vin_reqs)) != NULL) {
		vio9p_req_free_impl(vin, vnr);
	}
	kmem_free(vin, sizeof (*vin));
	ddi_soft_state_free(vio9p_state, instance);
	return (DDI_FAILURE);
}

static int
vio9p_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vio9p_t *vin = ddi_get_driver_private(dip);

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	mutex_enter(&vin->vin_mutex);

	if (vin->vin_open) {
		mutex_exit(&vin->vin_mutex);
		dev_err(dip, CE_WARN, "cannot detach while open");
		return (DDI_FAILURE);
	}

	/*
	 * If a request was submitted to the hypervisor but never completed, it
	 * may still be active even though the device has been closed.  Ensure
	 * that all remaining requests are on the free list:
	 */
	for (vio9p_req_t *vnr = list_head(&vin->vin_reqs);
	    vnr != NULL; vnr = list_next(&vin->vin_reqs, vnr)) {
		if (!list_link_active(&vnr->vnr_link_free)) {
			mutex_exit(&vin->vin_mutex);
			dev_err(dip, CE_WARN, "cannot detach with requests");
			return (DDI_FAILURE);
		}
	}

	/*
	 * Empty the free list:
	 */
	for (;;) {
		vio9p_req_t *vir = list_remove_head(&vin->vin_req_freelist);
		if (vir == NULL) {
			break;
		}
		vin->vin_req_nfreelist--;
		vio9p_req_free_impl(vin, vir);
	}
	VERIFY0(vin->vin_req_nfreelist);
	VERIFY(list_is_empty(&vin->vin_req_freelist));

	VERIFY(list_is_empty(&vin->vin_completes));
	VERIFY(list_is_empty(&vin->vin_reqs));

	/*
	 * Tear down the Virtio framework before freeing the rest of the
	 * resources.  This will ensure the interrupt handlers are no longer
	 * running.
	 */
	virtio_fini(vin->vin_virtio, B_FALSE);

	mutex_exit(&vin->vin_mutex);
	mutex_destroy(&vin->vin_mutex);

	ddi_soft_state_free(vio9p_state, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

static int
vio9p_quiesce(dev_info_t *dip)
{
	vio9p_t *vin;

	if ((vin = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	return (virtio_quiesce(vin->vin_virtio));
}

static int
vio9p_open(dev_t *dev, int flag, int otyp, cred_t *cred)
{
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	if (!(flag & FEXCL)) {
		return (EINVAL);
	}

	vio9p_t *vin = ddi_get_soft_state(vio9p_state, getminor(*dev));
	if (vin == NULL) {
		return (ENXIO);
	}

	mutex_enter(&vin->vin_mutex);
	if (vin->vin_open) {
		mutex_exit(&vin->vin_mutex);
		return (EBUSY);
	}
	vin->vin_open = true;

	vin->vin_generation++;
	if (vin->vin_generation == 0) {
		vin->vin_generation++;
	}

	mutex_exit(&vin->vin_mutex);
	return (0);
}

static int
vio9p_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	vio9p_t *vin = ddi_get_soft_state(vio9p_state, getminor(dev));
	if (vin == NULL) {
		return (ENXIO);
	}

	mutex_enter(&vin->vin_mutex);
	if (!vin->vin_open) {
		mutex_exit(&vin->vin_mutex);
		return (EIO);
	}

	/*
	 * Free all completed requests that have not yet been read:
	 */
	vio9p_req_t *vnr;
	while ((vnr = list_remove_head(&vin->vin_completes)) != NULL) {
		vio9p_req_free(vin, vnr);
	}

	vin->vin_open = false;
	mutex_exit(&vin->vin_mutex);
	return (0);
}

static int
vio9p_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred,
    int *rvalp)
{
	vio9p_t *vin = ddi_get_soft_state(vio9p_state, getminor(dev));
	if (vin == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	case VIO9P_IOC_MOUNT_TAG:
		if (ddi_copyout(vin->vin_tag, (void *)arg,
		    sizeof (vin->vin_tag), mode) != 0) {
			return (EFAULT);
		}
		return (0);

	default:
		return (ENOTTY);
	}
}

static int
vio9p_read(dev_t dev, struct uio *uio, cred_t *cred)
{
	vio9p_req_t *vnr;
	vio9p_t *vin;

	if ((vin = ddi_get_soft_state(vio9p_state, getminor(dev))) == NULL) {
		return (ENXIO);
	}

	mutex_enter(&vin->vin_mutex);
again:
	if ((vnr = list_remove_head(&vin->vin_completes)) == NULL) {
		/*
		 * There is nothing to read right now.  Wait for something:
		 */
		if (cv_wait_sig(&vin->vin_cv, &vin->vin_mutex) == 0) {
			mutex_exit(&vin->vin_mutex);
			return (EINTR);
		}
		goto again;
	}

	/*
	 * Determine the size of the response message.
	 */
	uint32_t msz;
	bcopy(virtio_dma_va(vnr->vnr_dma_in, 0), &msz, sizeof (msz));
	msz = LE_32(msz);
	if (msz > virtio_dma_size(vnr->vnr_dma_in)) {
		msz = virtio_dma_size(vnr->vnr_dma_in);
	}

	if (msz > uio->uio_resid) {
		/*
		 * Tell the consumer they are going to need a bigger
		 * buffer.
		 */
		list_insert_head(&vin->vin_completes, vnr);
		mutex_exit(&vin->vin_mutex);
		return (EOVERFLOW);
	}

	mutex_exit(&vin->vin_mutex);
	int e = uiomove(virtio_dma_va(vnr->vnr_dma_in, 0), msz, UIO_READ, uio);
	mutex_enter(&vin->vin_mutex);

	if (e == 0) {
		vio9p_req_free(vin, vnr);
	} else {
		/*
		 * Put the response back in the list for another try, so that
		 * we do not drop any messages:
		 */
		list_insert_head(&vin->vin_completes, vnr);
	}

	mutex_exit(&vin->vin_mutex);
	return (e);
}

static int
vio9p_write(dev_t dev, struct uio *uio, cred_t *cred)
{
	size_t wsz = uio->uio_resid;
	if (wsz < 7) {
		/*
		 * Requests should be well-formed 9P messages.  They must
		 * contain at least 7 bytes: msize[4] + type[1] + tag[2].
		 */
		return (EINVAL);
	} else if (wsz > VIRTIO_9P_REQ_SIZE) {
		return (ENOSPC);
	}

	vio9p_t *vin = ddi_get_soft_state(vio9p_state, getminor(dev));
	if (vin == NULL) {
		return (ENXIO);
	}

	mutex_enter(&vin->vin_mutex);
	vio9p_req_t *vnr = vio9p_req_alloc(vin, KM_NOSLEEP);
	if (vnr == NULL) {
		mutex_exit(&vin->vin_mutex);
		return (ENOMEM);
	}
	vnr->vnr_generation = vin->vin_generation;
	VERIFY3U(wsz, <=, virtio_dma_size(vnr->vnr_dma_out));

	mutex_exit(&vin->vin_mutex);
	int e = uiomove(virtio_dma_va(vnr->vnr_dma_out, 0), wsz, UIO_WRITE,
	    uio);
	mutex_enter(&vin->vin_mutex);

	if (e == 0) {
		virtio_dma_sync(vnr->vnr_dma_out, DDI_DMA_SYNC_FORDEV);
		virtio_chain_submit(vnr->vnr_chain, B_TRUE);
	} else {
		vio9p_req_free(vin, vnr);
	}

	mutex_exit(&vin->vin_mutex);
	return (e);
}

int
_init(void)
{
	int r;

	if ((r = ddi_soft_state_init(&vio9p_state, sizeof (vio9p_t), 0)) != 0) {
		return (r);
	}

	if ((r = mod_install(&vio9p_modlinkage)) != 0) {
		ddi_soft_state_fini(&vio9p_state);
	}

	return (r);
}

int
_fini(void)
{
	int r;

	if ((r = mod_remove(&vio9p_modlinkage)) != 0) {
		return (r);
	}

	ddi_soft_state_fini(&vio9p_state);

	return (r);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vio9p_modlinkage, modinfop));
}
