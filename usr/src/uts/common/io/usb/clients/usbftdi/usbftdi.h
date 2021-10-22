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
 * Copyright 2021 Oxide Computer Company
 */

#ifndef _USBSER_USBFTDI_USBFTDI_H
#define	_USBSER_USBFTDI_USBFTDI_H

/*
 * USB FTDI definitions
 */

#include <sys/types.h>
#include <sys/dditypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum uftdi_state {
	UFTDI_ST_ATTACHING = 0,
	UFTDI_ST_CLOSED,
	UFTDI_ST_OPENING,
	UFTDI_ST_OPEN,
	UFTDI_ST_CLOSING,
	UFTDI_ST_DETACHING,
} uftdi_state_t;

typedef enum uftdi_flags {
	UFTDI_FL_USB_CONNECTED =	(1 << 0),
} uftdi_flags_t;

typedef enum uftdi_modem_control {
	UFTDI_MODEM_RTS =		(1 << 0),
	UFTDI_MODEM_DTR =		(1 << 1),
} uftdi_modem_control_t;

typedef enum utfdi_device_type {
	UFTDI_DEVICE_UNKNOWN = 0,
	UFTDI_DEVICE_OLD,
	UFTDI_DEVICE_FT232A,
	UFTDI_DEVICE_FT232B,
	UFTDI_DEVICE_FT232R,
	UFTDI_DEVICE_FT232H,
	UFTDI_DEVICE_FT2232C,
	UFTDI_DEVICE_FT2232H,
	UFTDI_DEVICE_FT4232H,
	UFTDI_DEVICE_FTX,
} utfdi_device_type_t;

typedef enum uftdi_setup {
	UFTDI_SETUP_USB_ATTACH =	(1 << 0),
	UFTDI_SETUP_MUTEX =		(1 << 1),
	UFTDI_SETUP_SERDEV =		(1 << 2),
} uftdi_setup_t;

typedef enum uftdi_pipe_state {
	UFTDI_PIPE_CLOSED = 0,
	UFTDI_PIPE_IDLE,
	UFTDI_PIPE_BUSY,
} uftdi_pipe_state_t;

typedef struct uftdi_regs {
	uint16_t			ur_baud;
	uint16_t			ur_data;
	uint16_t			ur_timer;
	uint16_t			ur_flowval;
	uint8_t				ur_flowproto;
} uftdi_regs_t;

typedef struct uftdi_speed_params {
	uint16_t			usp_baud;
	uint16_t			usp_timer;
} uftdi_speed_params_t;

typedef struct uftdi_pipe {
	uftdi_pipe_state_t		up_state;
	usb_pipe_handle_t		up_pipe;
	size_t				up_bufsz;
} uftdi_pipe_t;

/*
 * per device state structure
 */
typedef struct uftdi {
	kmutex_t			uf_mutex;
	kcondvar_t			uf_cv;

	dev_info_t			*uf_dip;
	serdev_handle_t			*uf_serdev;

	uftdi_setup_t			uf_setup;
	uftdi_state_t			uf_state;
	uftdi_flags_t			uf_flags;

	/*
	 * FTDI port number, as passed in control messages, and other device
	 * identification information:
	 */
	uint8_t				uf_port;
	uint16_t			uf_device_version;
	utfdi_device_type_t		uf_device_type;

	/*
	 * To modify USB device state, you must uftdi_usb_change_start() to
	 * install the current thread as USB device state owner.
	 * XXX
	 */
	kthread_t			*uf_usb_thread;
	usb_client_dev_data_t		*uf_usb_dev;
	uftdi_pipe_t			uf_pipe_in;
	uftdi_pipe_t			uf_pipe_out;

	mblk_t				*uf_rx_mp;
	mblk_t				*uf_tx_mp;

	/*
	 * Cached values of parameters sent to, and status received from, the
	 * device:
	 */
	uftdi_regs_t			uf_last_regs;
	uftdi_modem_control_t		uf_last_mctl;
	uint8_t				uf_last_msr; /* Modem Status Register */
	uint8_t				uf_last_lsr; /* Line Status Register */
	uint8_t				uf_last_rxerr; /* LSR RX errors */
} uftdi_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _USBSER_USBFTDI_USBFTDI_H */
